/**
 * AI War Room — Compare 4 AI models on the same prompt simultaneously
 * Route: /war-room
 */

import { useState, useRef, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "sonner";
import {
  Swords, Send, Loader2, Home, Clock, Copy, Check,
  Zap, Code2, MessageSquare, Shield, Bot, ChevronDown,
  ChevronUp, AlertCircle, Trophy, Key,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";

// ─── Types ───────────────────────────────────────────────────────────
interface ModelResult {
  provider: string;
  providerName: string;
  icon: string;
  color: string;
  content: string;
  duration: number;
  available: boolean;
  error: string | null;
}

// ─── Provider placeholders ────────────────────────────────────────────
const PLACEHOLDERS: Record<string, { name: string; icon: string; color: string }> = {
  claude:    { name: "Claude Opus",      icon: "🟣", color: "#7C3AED" },
  gpt4:      { name: "Claude Haiku",     icon: "🟡", color: "#F59E0B" },
  gemini:    { name: "Gemini Flash",     icon: "🔵", color: "#3B82F6" },
  geminiPro: { name: "Gemini Pro",       icon: "💎", color: "#06B6D4" },
  deepseek:  { name: "DeepSeek R1",      icon: "⚡", color: "#F59E0B" },
};

// ─── Model Card ───────────────────────────────────────────────────────
function ModelCard({
  provider,
  result,
  isLoading,
  rank,
}: {
  provider: string;
  result?: ModelResult;
  isLoading: boolean;
  rank?: number;
}) {
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const contentRef = useRef<HTMLDivElement>(null);
  const isLong = (result?.content?.length || 0) > 600;

  const handleCopy = () => {
    if (!result?.content) return;
    navigator.clipboard.writeText(result.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success("تم النسخ");
  };

  const speedColor = (ms: number) => {
    if (ms < 5000) return "text-emerald-400";
    if (ms < 15000) return "text-amber-400";
    return "text-red-400";
  };

  // Use the specific provider's placeholder — no fallback to claude
  const ph = PLACEHOLDERS[provider] ?? PLACEHOLDERS.claude;
  const name = result?.providerName || ph.name;
  const icon = result?.icon || ph.icon;
  const color = result?.color || ph.color;
  const isAvailable = result ? result.available !== false : true;
  const hasError = result !== undefined && !isAvailable && !isLoading;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="relative flex flex-col rounded-2xl border bg-card overflow-hidden"
      style={{ borderColor: isLoading ? "transparent" : `${color}40` }}
    >
      {/* Rank badge */}
      {rank === 1 && result?.available && !isLoading && (
        <div className="absolute top-3 left-3 z-10">
          <span className="flex items-center gap-1 bg-amber-500/20 text-amber-400 text-[10px] font-bold px-2 py-0.5 rounded-full border border-amber-500/30">
            <Trophy className="w-3 h-3" /> الأسرع
          </span>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border"
        style={{ background: `${color}10` }}>
        <div className="flex items-center gap-2">
          <span className="text-xl">{icon}</span>
          <div>
            <h3 className="font-bold text-sm">{name}</h3>
            {result && !hasError && (
              <span className={`text-[10px] ${speedColor(result.duration)} flex items-center gap-1`}>
                <Clock className="w-2.5 h-2.5" />
                {(result.duration / 1000).toFixed(1)}s
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          {isLoading && (
            <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
              <Loader2 className="w-3 h-3 animate-spin" />
              يفكر...
            </span>
          )}
          {result?.available && result.content && (
            <button
              onClick={handleCopy}
              className="p-1.5 rounded hover:bg-secondary transition-colors text-muted-foreground hover:text-foreground"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 p-4 overflow-hidden">
        {isLoading ? (
          <div className="space-y-2">
            {[100, 80, 90, 60, 75].map((w, i) => (
              <div key={i} className="h-3 bg-muted/50 rounded animate-pulse" style={{ width: `${w}%` }} />
            ))}
          </div>
        ) : hasError ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 py-6 text-center">
            <div className="w-10 h-10 rounded-full bg-muted flex items-center justify-center">
              <Key className="w-5 h-5 text-muted-foreground" />
            </div>
            <div>
              {result?.error?.includes("429") || result?.error?.includes("quota") ? (
                <>
                  <p className="text-sm font-medium text-muted-foreground mb-1">تجاوزت الحصة اليومية</p>
                  <p className="text-xs text-muted-foreground/60">رصيد API منتهٍ، يُجدد قريباً</p>
                </>
              ) : result?.error?.includes("API key not configured") ? (
                <>
                  <p className="text-sm font-medium text-muted-foreground mb-1">النموذج غير مفعّل</p>
                  <p className="text-xs text-muted-foreground/60">
                    أضف <code className="bg-muted px-1 rounded text-[10px]">{name.replace("-", "_").toUpperCase()}_API_KEY</code> في Secrets
                  </p>
                </>
              ) : (
                <>
                  <p className="text-sm font-medium text-muted-foreground mb-1">خطأ في الاتصال</p>
                  <p className="text-xs text-muted-foreground/60 max-w-[160px]">{result?.error?.slice(0, 80)}</p>
                </>
              )}
            </div>
          </div>
        ) : (
          <div>
            <div
              ref={contentRef}
              className={`text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap ${isLong && !expanded ? "max-h-48 overflow-hidden" : ""}`}
            >
              {result?.content}
            </div>
            {isLong && (
              <button
                onClick={() => setExpanded(!expanded)}
                className="mt-2 flex items-center gap-1 text-xs text-primary hover:underline"
              >
                {expanded ? <><ChevronUp className="w-3 h-3" /> أقل</> : <><ChevronDown className="w-3 h-3" /> المزيد</>}
              </button>
            )}
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────
export default function WarRoom() {
  const { isAuthenticated, loading: authLoading } = useAuth();
  const [prompt, setPrompt] = useState("");
  const [results, setResults] = useState<ModelResult[]>([]);
  const [hasRun, setHasRun] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const { data: modelsData } = trpc.agent.getProviders.useQuery(undefined, {
    staleTime: 60_000,
  });
  const modelAvailability: Record<string, boolean> = {};
  (modelsData ?? []).forEach((m: any) => { modelAvailability[m.id] = m.available; });

  const warRoomMutation = trpc.agent.warRoom.useMutation({
    onSuccess: (data: ModelResult[]) => {
      setResults(data);
      const successful = data.filter((r) => r.available && !r.error).length;
      toast.success(`اكتمل! ${successful} نموذج أجاب`);
    },
    onError: (err: { data?: { code?: string }; message: string }) => {
      setHasRun(false);
      setResults([]);
      if (err.data?.code === "TOO_MANY_REQUESTS") {
        toast.error("نفدت نقاطك اليومية. يُجدد الرصيد غداً أو قم بالترقية.");
      } else {
        toast.error(`خطأ: ${err.message}`);
      }
    },
  });

  const handleSubmit = () => {
    if (!prompt.trim() || warRoomMutation.isPending) return;
    setResults([]);
    setHasRun(true);
    warRoomMutation.mutate({ prompt: prompt.trim() });
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      handleSubmit();
    }
  };

  // AI Judge
  const [judgeResult, setJudgeResult] = useState("");
  const [isJudging, setIsJudging] = useState(false);

  const handleJudge = async () => {
    const available = results.filter(r => r.available && r.content);
    if (available.length < 2) { toast.error("يجب أن يكون هناك إجابتان على الأقل"); return; }
    setIsJudging(true);
    try {
      const summaries = available.map(r => `[${r.providerName}] (${(r.duration/1000).toFixed(1)}s):\n${r.content.substring(0, 800)}`).join("\n\n---\n\n");
      const r = await fetch("/api/prompt-factory/test", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prompt: `أنت حكم محايد خبير. قارن بين إجابات ${available.length} نماذج AI على نفس السؤال.

لكل نموذج قيّم (من 10):
1. دقة المعلومات
2. شمولية الإجابة
3. وضوح الأسلوب
4. فائدة عملية

ثم اختر الفائز مع التبرير. اكتب بالعربية.`,
          testInput: `السؤال: ${prompt}\n\nالإجابات:\n${summaries}`,
        }),
      });
      const d = await r.json();
      setJudgeResult(d.result || "فشل التقييم");
      toast.success("✅ تم التقييم!");
    } catch { toast.error("فشل التقييم"); }
    setIsJudging(false);
  };

  // Compute ranking by speed
  const rankedResults = [...results]
    .filter(r => r.available && !r.error && r.duration > 0)
    .sort((a, b) => a.duration - b.duration);
  const fastestProvider = rankedResults[0]?.provider;

  const PROVIDER_ORDER = ["claude", "gpt4", "gemini", "geminiPro", "deepseek"];

  const getResultForProvider = (provider: string) =>
    results.find(r => r.provider === provider);

  // ─── Auth Gate ────────────────────────────────────────────────────
  if (authLoading) {
    return (
      <div className="h-screen flex items-center justify-center bg-background">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="h-screen flex items-center justify-center bg-background p-4">
        <div className="bg-card border border-border rounded-2xl p-8 max-w-md w-full text-center space-y-4">
          <Swords className="w-16 h-16 mx-auto text-primary opacity-60" />
          <h2 className="text-2xl font-bold">AI War Room</h2>
          <p className="text-muted-foreground">سجّل دخولك للوصول إلى غرفة المعارك</p>
          <Button asChild className="w-full">
            <a href={getLoginUrl()}>تسجيل الدخول</a>
          </Button>
        </div>
      </div>
    );
  }

  // ─── Main UI ──────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col" dir="rtl">
      {/* Top Bar */}
      <header className="h-12 bg-card border-b border-border flex items-center justify-between px-4 shrink-0">
        <div className="flex items-center gap-3">
          <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">
            <Home className="w-4 h-4" />
          </Link>
          <div className="w-px h-5 bg-border" />
          <Link href="/chat" className="flex items-center gap-1.5 text-muted-foreground hover:text-primary transition-colors text-sm">
            <MessageSquare className="w-3.5 h-3.5" /> دردشة
          </Link>
          <Link href="/agent" className="flex items-center gap-1.5 text-muted-foreground hover:text-primary transition-colors text-sm">
            <Bot className="w-3.5 h-3.5" /> وكيل AI
          </Link>
          <div className="w-px h-5 bg-border" />
          <Swords className="w-5 h-5 text-primary" />
          <span className="font-bold text-sm">AI War Room</span>
          <span className="text-xs bg-primary/10 text-primary px-2 py-0.5 rounded-full">⚔️ معركة النماذج</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {Object.entries(PLACEHOLDERS).map(([id, ph]) => {
            const available = modelsData ? (modelAvailability[id] ?? false) : id === "claude";
            return (
              <span key={id} className={`flex items-center gap-1 ${available ? "" : "opacity-40"}`}>
                <div className={`w-2 h-2 rounded-full`} style={{ background: available ? ph.color : `${ph.color}50` }} />
                {ph.name}
              </span>
            );
          })}
        </div>
      </header>

      <div className="flex-1 flex flex-col max-w-7xl w-full mx-auto px-4 py-6 gap-6">
        {/* Hero */}
        {!hasRun && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center space-y-3 pt-4"
          >
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-primary/10 mb-2">
              <Swords className="w-8 h-8 text-primary" />
            </div>
            <h1 className="text-3xl font-heading font-bold">AI War Room</h1>
            <p className="text-muted-foreground max-w-xl mx-auto">
              اكتب سؤالاً أو طلباً وشاهد كيف يجيب كل نموذج ذكاء اصطناعي. قارن السرعة والجودة والأسلوب!
            </p>

            {/* Example prompts */}
            <div className="flex flex-wrap gap-2 justify-center pt-2">
              {[
                "اشرح لي مفهوم الذكاء الاصطناعي بطريقة بسيطة",
                "اكتب كوداً لفرز قائمة في Python",
                "ما هي أفضل استراتيجيات التسويق الرقمي؟",
                "اكتب قصيدة عن التكنولوجيا",
              ].map((example) => (
                <button
                  key={example}
                  onClick={() => { setPrompt(example); textareaRef.current?.focus(); }}
                  className="text-xs bg-secondary hover:bg-secondary/80 px-3 py-1.5 rounded-full transition-colors text-muted-foreground hover:text-foreground"
                >
                  {example}
                </button>
              ))}
            </div>
          </motion.div>
        )}

        {/* Prompt Input */}
        <div className="bg-card border border-border rounded-2xl p-4 space-y-3">
          <textarea
            ref={textareaRef}
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="اكتب سؤالك أو طلبك هنا... (Ctrl+Enter للإرسال)"
            className="w-full bg-transparent resize-none text-sm placeholder:text-muted-foreground/50 outline-none min-h-[80px] max-h-[200px]"
            disabled={warRoomMutation.isPending}
          />
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              {prompt.length}/5000 حرف • {warRoomMutation.isPending ? "جاري المعركة..." : "Ctrl+Enter للإرسال"}
            </span>
            <Button
              onClick={handleSubmit}
              disabled={!prompt.trim() || warRoomMutation.isPending}
              className="gap-2 bg-primary hover:bg-primary/90 font-bold"
            >
              {warRoomMutation.isPending ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> جاري المعركة...</>
              ) : (
                <><Swords className="w-4 h-4" /> ⚔️ ابدأ المعركة!</>
              )}
            </Button>
          </div>
        </div>

        {/* Stats bar when results available */}
        <AnimatePresence>
          {results.length > 0 && !warRoomMutation.isPending && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              className="flex flex-wrap gap-4 text-sm bg-card border border-border rounded-xl px-4 py-3"
            >
              {results.filter(r => r.available && r.duration > 0).map(r => (
                <div key={r.provider} className="flex items-center gap-1.5">
                  <span>{r.icon}</span>
                  <span className="font-medium">{r.providerName}</span>
                  <span className={`text-xs ${r.duration < 5000 ? "text-emerald-400" : r.duration < 15000 ? "text-amber-400" : "text-red-400"}`}>
                    {(r.duration / 1000).toFixed(1)}s
                  </span>
                  {r.provider === fastestProvider && <Trophy className="w-3.5 h-3.5 text-amber-400" />}
                </div>
              ))}
              <div className="flex items-center gap-1 text-muted-foreground text-xs mr-auto">
                <Zap className="w-3 h-3" />
                {results.filter(r => r.available && !r.error).length}/{results.length} نماذج أجابت
              </div>
              {/* AI Judge Button */}
              <Button size="sm" variant="outline" onClick={handleJudge} disabled={isJudging || results.filter(r=>r.available && r.content).length < 2}
                className="gap-1.5 h-7 text-[10px] text-amber-400 border-amber-400/30 hover:bg-amber-400/10">
                {isJudging ? <><Loader2 className="w-3 h-3 animate-spin" /> يقيّم...</> : <><Trophy className="w-3 h-3" /> 🏆 حكم AI</>}
              </Button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* AI Judge Results */}
        {judgeResult && (
          <div className="bg-gradient-to-r from-amber-500/5 to-yellow-500/5 border border-amber-500/20 rounded-2xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-bold text-sm flex items-center gap-2"><Trophy className="w-4 h-4 text-amber-400" /> 🏆 تقييم الحكم AI</h3>
              <button onClick={() => { navigator.clipboard.writeText(judgeResult); toast.success("تم النسخ"); }} className="text-xs text-primary hover:underline">نسخ</button>
            </div>
            <div className="text-sm text-foreground/85 leading-relaxed whitespace-pre-wrap max-h-60 overflow-y-auto">{judgeResult}</div>
          </div>
        )}

        {/* Model Grid */}
        {hasRun && (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 flex-1">
            {PROVIDER_ORDER.map((prov) => {
              const result = getResultForProvider(prov);
              const isLoading = warRoomMutation.isPending && !result;
              const rank = result?.provider === fastestProvider ? 1 : undefined;

              return (
                <ModelCard
                  key={prov}
                  provider={prov}
                  result={result}
                  isLoading={isLoading}
                  rank={rank}
                />
              );
            })}
          </div>
        )}

        {/* Empty state */}
        {!hasRun && (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 opacity-30">
            {["claude", "gpt4", "gemini", "geminiPro", "deepseek"].map((provider) => {
              const ph: Record<string, { name: string; icon: string; color: string }> = {
                claude: { name: "Claude Opus", icon: "🟣", color: "#7C3AED" },
                gpt4: { name: "Claude Haiku", icon: "🟡", color: "#F59E0B" },
                gemini: { name: "Gemini Flash", icon: "🔵", color: "#3B82F6" },
                geminiPro: { name: "Gemini Pro", icon: "💎", color: "#06B6D4" },
                deepseek: { name: "DeepSeek R1", icon: "⚡", color: "#F59E0B" },
              };
              const p = ph[provider];
              return (
                <div key={provider} className="rounded-2xl border border-border bg-card overflow-hidden h-40">
                  <div className="flex items-center gap-2 px-4 py-3 border-b border-border" style={{ background: `${p.color}10` }}>
                    <span className="text-xl">{p.icon}</span>
                    <span className="font-bold text-sm">{p.name}</span>
                  </div>
                  <div className="p-4 space-y-2">
                    {[80, 65, 75].map((w, i) => (
                      <div key={i} className="h-3 bg-muted/30 rounded" style={{ width: `${w}%` }} />
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Note about models */}
        <div className="text-center text-xs text-muted-foreground/50 pb-4">
          <AlertCircle className="w-3 h-3 inline mr-1" />
          النماذج الرمادية تحتاج مفتاح API — أضف <code className="bg-muted px-1 rounded">OPENAI_API_KEY</code>،{" "}
          <code className="bg-muted px-1 rounded">GEMINI_API_KEY</code>،{" "}
          <code className="bg-muted px-1 rounded">DEEPSEEK_API_KEY</code> في Secrets لتفعيلها
        </div>
      </div>
    </div>
  );
}
