/**
 * Trading Analysis — Live Forex/Gold market analysis with 3 AI models (Claude Opus 4, Gemini Pro, DeepSeek)
 * Route: /war-room
 * Features: Manual analysis, Quick Scan (auto-signals with 1-min refresh), Economic News Filter, Telegram send
 */

import { useState, useRef, useEffect, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "sonner";
import {
  TrendingUp, TrendingDown, Minus, Home, Loader2, BarChart3,
  RefreshCw, Shield, AlertTriangle, ChevronDown, ChevronUp,
  Activity, Target, StopCircle, Zap, Trophy, Send,
  Newspaper, Scan, CheckCircle2, XCircle, Clock, ToggleLeft, ToggleRight,
  Crosshair, Radio,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";

// ─── Types ────────────────────────────────────────────────────────────
interface AnalysisResult {
  provider: string;
  providerName: string;
  icon: string;
  color: string;
  signal: "BUY" | "SELL" | "HOLD";
  confidence: number;
  reasoning: string;
  entryZone: string;
  stopLoss: string;
  takeProfit: string;
  risk: "LOW" | "MEDIUM" | "HIGH";
  duration: number;
  available: boolean;
  error: string | null;
}

interface StrategySignal {
  id: string;
  name: string;
  signal: "BUY" | "SELL" | "NEUTRAL";
  strength: number;
  desc: string;
  emoji: string;
}

interface FilterResult {
  id: string;
  name: string;
  passed: boolean;
  allowsBuy: boolean;
  allowsSell: boolean;
  desc: string;
  emoji: string;
}

interface EconomicNewsItem {
  date: string;
  time: string;
  currency: string;
  title: string;
  impact: "High" | "Medium" | "Low";
  forecast: string;
  previous: string;
  actual: string;
}

interface TradingData {
  pair: string;
  timeframe: string;
  currentPrice: number;
  indicators: {
    rsi: number;
    sma20: number;
    sma50: number;
    sma200: number | null;
    macd: { macd: number; signal: number; histogram: number };
    bb: { upper: number; lower: number; middle: number };
    atr: number;
    stoch?: { k: number; d: number };
    williamsR?: number;
    adx?: { adx: number; pdi: number; mdi: number };
    pivots?: { pivot: number; r1: number; r2: number; s1: number; s2: number };
  };
  strategySignals: StrategySignal[];
  filterResults: FilterResult[];
  economicNews?: EconomicNewsItem[];
  results: AnalysisResult[];
}

// ─── Currency Pairs & Timeframes ──────────────────────────────────────
const PAIRS = [
  { id: "EURUSD", label: "EUR/USD", flag: "🇪🇺🇺🇸", tv: "FX:EURUSD", desc: "اليورو / الدولار" },
  { id: "USDJPY", label: "USD/JPY", flag: "🇺🇸🇯🇵", tv: "FX:USDJPY", desc: "الدولار / الين" },
  { id: "GBPUSD", label: "GBP/USD", flag: "🇬🇧🇺🇸", tv: "FX:GBPUSD", desc: "الإسترليني / الدولار" },
  { id: "GBPJPY", label: "GBP/JPY", flag: "🇬🇧🇯🇵", tv: "FX:GBPJPY", desc: "الإسترليني / الين" },
  { id: "USDCHF", label: "USD/CHF", flag: "🇺🇸🇨🇭", tv: "FX:USDCHF", desc: "الدولار / الفرنك" },
  { id: "AUDUSD", label: "AUD/USD", flag: "🇦🇺🇺🇸", tv: "FX:AUDUSD", desc: "الأسترالي / الدولار" },
  { id: "NZDUSD", label: "NZD/USD", flag: "🇳🇿🇺🇸", tv: "FX:NZDUSD", desc: "النيوزيلندي / الدولار" },
  { id: "USDCAD", label: "USD/CAD", flag: "🇺🇸🇨🇦", tv: "FX:USDCAD", desc: "الدولار / الكندي" },
  { id: "EURGBP", label: "EUR/GBP", flag: "🇪🇺🇬🇧", tv: "FX:EURGBP", desc: "اليورو / الإسترليني" },
  { id: "EURJPY", label: "EUR/JPY", flag: "🇪🇺🇯🇵", tv: "FX:EURJPY", desc: "اليورو / الين" },
  { id: "EURCHF", label: "EUR/CHF", flag: "🇪🇺🇨🇭", tv: "FX:EURCHF", desc: "اليورو / الفرنك" },
  { id: "AUDCAD", label: "AUD/CAD", flag: "🇦🇺🇨🇦", tv: "FX:AUDCAD", desc: "الأسترالي / الكندي" },
  { id: "XAUUSD", label: "XAU/USD", flag: "🥇", tv: "TVC:GOLD", desc: "الذهب / الدولار" },
  { id: "XAGUSD", label: "XAG/USD", flag: "🥈", tv: "TVC:SILVER", desc: "الفضة / الدولار" },
  { id: "BTCUSD", label: "BTC/USD", flag: "₿", tv: "BINANCE:BTCUSDT", desc: "البيتكوين / الدولار" },
  { id: "ETHUSD", label: "ETH/USD", flag: "⟠", tv: "BINANCE:ETHUSDT", desc: "الإيثريوم / الدولار" },
  { id: "USOIL", label: "US Oil", flag: "🛢️", tv: "TVC:USOIL", desc: "النفط الأمريكي" },
  { id: "US30", label: "US30/DJI", flag: "🏛️", tv: "CAPITALCOM:US30", desc: "مؤشر داو جونز" },
];

const TIMEFRAMES = [
  { id: "1min",  label: "1M",  icon: "⚡", tv: "1"  },
  { id: "5min",  label: "5M",  icon: "🕐", tv: "5"  },
  { id: "15min", label: "15M", icon: "🕒", tv: "15" },
  { id: "30min", label: "30M", icon: "🕧", tv: "30" },
  { id: "1h",    label: "1H",  icon: "⏰", tv: "60" },
];

const TF_ICON: Record<string, string> = {
  "1min": "⚡", "5min": "🕐", "15min": "🕒", "30min": "🕧", "1h": "⏰",
};
const TF_LABEL: Record<string, string> = {
  "1min": "1M", "5min": "5M", "15min": "15M", "30min": "30M", "1h": "1H",
};

// 3 AI Providers: Claude Opus 4, Gemini Pro, DeepSeek
const PROVIDER_ORDER = ["claude", "geminiPro", "deepseek"];

// ─── Quick Scan Panel with Auto-Refresh ───────────────────────────────
function QuickScanPanel({ onSelectPair }: { onSelectPair: (pair: string, tf: string) => void }) {
  const [scanTf, setScanTf]         = useState("15min");
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [countdown, setCountdown]   = useState(60);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const scanMut = trpc.tradingAnalysis.quickScan.useMutation({
    onSuccess: (data) => {
      const high = data.highQuality;
      if (high.length > 0) {
        toast.success(`🎯 ${high.length} إشارة عالية الجودة اكتُشفت!`);
      }
    },
    onError: (err) => toast.error(`خطأ في الفحص: ${err.message}`),
  });

  const runScan = useCallback(() => {
    setCountdown(60);
    scanMut.mutate({ timeframe: scanTf as any });
  }, [scanTf]);

  // Auto-refresh every 60 seconds
  useEffect(() => {
    if (autoRefresh) {
      runScan();
      timerRef.current = setInterval(runScan, 60000);
      countdownRef.current = setInterval(() => {
        setCountdown(prev => (prev <= 1 ? 60 : prev - 1));
      }, 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
      if (countdownRef.current) clearInterval(countdownRef.current);
      timerRef.current = null;
      countdownRef.current = null;
      setCountdown(60);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      if (countdownRef.current) clearInterval(countdownRef.current);
    };
  }, [autoRefresh, scanTf]);

  // Re-run if timeframe changes while auto-refresh is on
  useEffect(() => {
    if (autoRefresh) {
      if (timerRef.current) clearInterval(timerRef.current);
      if (countdownRef.current) clearInterval(countdownRef.current);
      runScan();
      timerRef.current = setInterval(runScan, 60000);
      countdownRef.current = setInterval(() => {
        setCountdown(prev => (prev <= 1 ? 60 : prev - 1));
      }, 1000);
    }
  }, [scanTf]);

  const QUALITY_COLORS = {
    HIGH:   "border-emerald-500/40 bg-emerald-500/8",
    MEDIUM: "border-amber-500/35 bg-amber-500/8",
    LOW:    "border-white/10 bg-white/3",
  };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border border-violet-500/25 bg-violet-500/5 backdrop-blur p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Scan className="w-4 h-4 text-violet-400" />
          <span className="font-bold text-sm text-white">الفحص التلقائي</span>
          <span className="text-xs text-white/40">(بدون نقاط)</span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Timeframe */}
          <select
            value={scanTf}
            onChange={e => setScanTf(e.target.value)}
            className="text-xs bg-white/10 border border-white/20 rounded-lg px-2 py-1.5 text-white/80"
          >
            {TIMEFRAMES.map(tf => (
              <option key={tf.id} value={tf.id}>{tf.icon} {tf.label}</option>
            ))}
          </select>

          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-all ${
              autoRefresh
                ? "bg-emerald-500/20 border-emerald-500/40 text-emerald-400"
                : "bg-white/5 border-white/15 text-white/50 hover:bg-white/10"
            }`}
          >
            {autoRefresh
              ? <ToggleRight className="w-3.5 h-3.5" />
              : <ToggleLeft  className="w-3.5 h-3.5" />
            }
            تلقائي
          </button>

          {/* Countdown */}
          {autoRefresh && (
            <div className="flex items-center gap-1 text-xs text-emerald-400 font-mono">
              <Clock className="w-3 h-3" />
              {countdown}s
            </div>
          )}

          {/* Manual scan */}
          <Button
            size="sm"
            onClick={runScan}
            disabled={scanMut.isPending}
            className="gap-1.5 bg-violet-600 hover:bg-violet-700 text-white text-xs"
          >
            {scanMut.isPending
              ? <><Loader2 className="w-3 h-3 animate-spin" /> فحص...</>
              : <><Scan className="w-3 h-3" /> فحص الكل</>
            }
          </Button>
        </div>
      </div>

      {/* Auto-refresh status bar */}
      {autoRefresh && (
        <div className="w-full bg-white/10 rounded-full h-1 overflow-hidden">
          <motion.div
            className="h-full bg-emerald-500"
            initial={{ width: "100%" }}
            animate={{ width: `${(countdown / 60) * 100}%` }}
            transition={{ duration: 1, ease: "linear" }}
          />
        </div>
      )}

      {/* Results grid */}
      {scanMut.data && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
            {scanMut.data.signals.map((sig) => (
              <button
                key={sig.pair}
                onClick={() => {
                  if (sig.signal !== "NEUTRAL") onSelectPair(sig.pair, sig.timeframe);
                }}
                disabled={sig.signal === "NEUTRAL"}
                className={`rounded-xl border p-3 text-right transition-all ${
                  QUALITY_COLORS[sig.quality as keyof typeof QUALITY_COLORS] || QUALITY_COLORS.LOW
                } ${sig.signal !== "NEUTRAL" ? "cursor-pointer hover:scale-[1.02]" : "cursor-default opacity-50"}`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span>{sig.flag}</span>
                  <div className="flex items-center gap-1">
                    <span className="text-[10px] text-white/40 font-mono">
                      {TF_ICON[sig.timeframe] ?? "⏱"}{TF_LABEL[sig.timeframe] ?? sig.timeframe}
                    </span>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${
                      sig.signal === "BUY"  ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" :
                      sig.signal === "SELL" ? "bg-red-500/20 text-red-400 border-red-500/30" :
                      "bg-white/8 text-white/40 border-white/10"
                    }`}>
                      {sig.signal === "BUY" ? "شراء" : sig.signal === "SELL" ? "بيع" : "محايد"}
                    </span>
                  </div>
                </div>
                <div className="text-xs font-bold text-white/90">{sig.pair.replace(/(.{3})(.{3})/, "$1/$2")}</div>
                <div className="text-[10px] text-white/45 mt-0.5">
                  RSI {sig.rsi} | {Math.max(sig.buySigs, sig.sellSigs)}/{sig.buySigs + sig.sellSigs} استراتيجية
                </div>
                {sig.quality === "HIGH" && (
                  <div className="mt-1.5 text-[10px] text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-2.5 h-2.5" /> اضغط للتحليل الكامل
                  </div>
                )}
              </button>
            ))}
          </div>

          {scanMut.data.highQuality.length > 0 && (
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400">
              🎯 {scanMut.data.highQuality.length} إشارة عالية الجودة — اضغط على البطاقة للتحليل الكامل بـ AI
            </div>
          )}

          {scanMut.data.aiSummary && scanMut.data.aiSummary.length > 0 && (
            <div className="p-3 rounded-xl bg-violet-500/10 border border-violet-500/20 space-y-2">
              <div className="text-xs font-bold text-violet-400 flex items-center gap-1.5">
                <Brain className="w-3.5 h-3.5" /> تقييم AI سريع للإشارات العالية
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {scanMut.data.aiSummary.map((ai: any) => (
                  <div key={ai.provider} className="rounded-lg bg-white/5 border border-white/10 p-2.5">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-bold text-white/80">{ai.icon} {ai.providerName}</span>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full ${
                        ai.signal === "BUY" ? "bg-emerald-500/20 text-emerald-400" :
                        ai.signal === "SELL" ? "bg-red-500/20 text-red-400" :
                        "bg-amber-500/20 text-amber-400"
                      }`}>
                        {ai.signal} {ai.confidence}%
                      </span>
                    </div>
                    <div className="text-[10px] text-white/50 leading-relaxed">{ai.reasoning}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="text-[10px] text-white/30 text-center">
            آخر فحص: {new Date(scanMut.data.scannedAt).toLocaleTimeString("ar-SA")}
            {autoRefresh && " · تجديد تلقائي كل دقيقة"}
          </div>
        </div>
      )}

      {!scanMut.data && !scanMut.isPending && (
        <div className="text-xs text-white/40 text-center py-2">
          اضغط "فحص الكل" أو فعّل التحديث التلقائي (كل دقيقة) لمراقبة الأزواق الـ5
        </div>
      )}
    </motion.div>
  );
}

// ─── Convergence Panel (التطابق) ──────────────────────────────────────
function ConvergencePanel({ onSelectPair }: { onSelectPair: (pair: string, tf: string) => void }) {
  const INTERVALS = [1, 2, 3, 5, 7, 10, 15];
  const statusQuery = trpc.tradingAnalysis.convergenceStatus.useQuery(undefined, { refetchInterval: 15000 });
  const toggleMut = trpc.tradingAnalysis.convergenceToggle.useMutation({ onSuccess: () => statusQuery.refetch() });
  const setIntMut = trpc.tradingAnalysis.convergenceSetInterval.useMutation({ onSuccess: () => statusQuery.refetch() });
  const scanNowMut = trpc.tradingAnalysis.convergenceScanNow.useMutation({
    onSuccess: (data) => {
      statusQuery.refetch();
      if (data.signals.length > 0) toast.success(`تم العثور على ${data.signals.length} إشارة تطابق!`);
      else toast("لم يُعثر على تطابق حالياً");
    },
    onError: (err) => toast.error(`خطأ: ${err.message}`),
  });

  const config = statusQuery.data?.config;
  const signals = statusQuery.data?.signals || [];
  const [expanded, setExpanded] = useState(true);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border border-amber-500/25 bg-amber-500/5 backdrop-blur p-4 space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-amber-400" />
          <span className="font-bold text-sm text-white">نظام التطابق</span>
          <span className="text-xs text-white/40">(3 فريمات × {9} أزواج)</span>
          {config?.enabled && (
            <span className="flex items-center gap-1 text-[10px] text-emerald-400">
              <Radio className="w-3 h-3 animate-pulse" /> مباشر
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={config?.intervalMinutes || 3}
            onChange={e => setIntMut.mutate({ intervalMinutes: parseInt(e.target.value) })}
            className="text-xs bg-white/10 border border-white/20 rounded-lg px-2 py-1.5 text-white/80"
          >
            {INTERVALS.map(m => (
              <option key={m} value={m}>{m} دقيقة</option>
            ))}
          </select>

          <button
            onClick={() => config && toggleMut.mutate({ enabled: !config.enabled })}
            className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-all ${
              config?.enabled
                ? "bg-emerald-500/20 border-emerald-500/40 text-emerald-400"
                : "bg-white/5 border-white/15 text-white/50 hover:bg-white/10"
            }`}
          >
            {config?.enabled
              ? <ToggleRight className="w-3.5 h-3.5" />
              : <ToggleLeft className="w-3.5 h-3.5" />
            }
            {config?.enabled ? "مفعّل" : "معطّل"}
          </button>

          <Button
            size="sm"
            onClick={() => scanNowMut.mutate()}
            disabled={scanNowMut.isPending}
            className="gap-1.5 bg-amber-600 hover:bg-amber-700 text-white text-xs"
          >
            {scanNowMut.isPending
              ? <><Loader2 className="w-3 h-3 animate-spin" /> فحص...</>
              : <><Crosshair className="w-3 h-3" /> فحص فوري</>
            }
          </Button>

          <button onClick={() => setExpanded(!expanded)} className="text-white/40 hover:text-white/70">
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      <div className="text-[10px] text-white/40">
        يفحص تطابق اتجاه <b>1م + 5م + 15م</b> لكل زوج — عند التطابق يؤكّد بـ AI ثم يُرسل إشارة تلقائياً للبوت + هنا
      </div>

      <AnimatePresence>
        {expanded && signals.length > 0 && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }}
            className="space-y-3">
            <div className="text-xs text-amber-400 font-bold flex items-center gap-1.5">
              <Trophy className="w-3.5 h-3.5" />
              آخر إشارات التطابق ({signals.length})
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 max-h-[400px] overflow-y-auto pr-1">
              {signals.slice(0, 12).map((sig: any, idx: number) => (
                <motion.button
                  key={`${sig.pair}-${sig.timestamp}`}
                  initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: idx * 0.05 }}
                  onClick={() => onSelectPair(sig.pair, "15min")}
                  className={`rounded-xl border p-3 text-right transition-all hover:scale-[1.02] cursor-pointer ${
                    sig.direction === "BUY"
                      ? "border-emerald-500/40 bg-emerald-500/8"
                      : "border-red-500/40 bg-red-500/8"
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-lg">{sig.flag}</span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                      sig.direction === "BUY"
                        ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                        : "bg-red-500/20 text-red-400 border-red-500/30"
                    }`}>
                      {sig.direction === "BUY" ? "شراء قوية" : "بيع قوي"}
                    </span>
                  </div>
                  <div className="text-xs font-bold text-white/90 mb-1">
                    {sig.pair.replace(/(.{3})(.{3})/, "$1/$2")}
                  </div>
                  <div className="text-[10px] text-white/60 mb-2">
                    السعر: {sig.price} | توافق: {sig.avgPct}%
                  </div>

                  <div className="space-y-1 mb-2">
                    {sig.tfDetails?.map((tf: any) => (
                      <div key={tf.tf} className="flex items-center justify-between text-[10px]">
                        <span className="text-white/50 font-mono">{tf.tf}</span>
                        <span className={tf.direction === "BUY" ? "text-emerald-400" : "text-red-400"}>
                          {tf.direction === "BUY" ? "🟢" : "🔴"} {tf.pct}% ({tf.buys}↑ {tf.sells}↓)
                        </span>
                      </div>
                    ))}
                  </div>

                  <div className="flex items-center justify-between text-[10px] border-t border-white/10 pt-1.5">
                    <span className="text-white/40">
                      AI: {sig.aiModels}/{sig.totalModels} | {sig.aiConfidence}%
                    </span>
                    <span className="text-white/30">
                      {new Date(sig.timestamp).toLocaleTimeString("ar-SA", { hour: "2-digit", minute: "2-digit" })}
                    </span>
                  </div>

                  {sig.newsWarnings?.length > 0 && (
                    <div className="mt-1.5 text-[10px] text-red-400 flex items-center gap-1">
                      <AlertTriangle className="w-2.5 h-2.5" /> تحذير أخبار
                    </div>
                  )}
                </motion.button>
              ))}
            </div>
          </motion.div>
        )}

        {expanded && signals.length === 0 && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className="text-xs text-white/40 text-center py-3">
            {config?.enabled
              ? "جاري المراقبة... ستظهر الإشارات عند اكتشاف تطابق"
              : "فعّل التطابق أو اضغط 'فحص فوري' للبدء"
            }
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ─── Economic News Filter Card (inline with analysis) ─────────────────
function NewsFilterCard({ news }: { news: EconomicNewsItem[] }) {
  const [expanded, setExpanded] = useState(false);
  const now = new Date();
  const upcomingHigh = news.filter(e => {
    if (!e.date || !e.time) return false;
    try {
      const t = new Date(e.date + " " + (e.time || "").replace("am", " AM").replace("pm", " PM"));
      const diffHours = (t.getTime() - now.getTime()) / 3600000;
      return e.impact === "High" && diffHours >= -1 && diffHours <= 3;
    } catch { return false; }
  });
  const passed = upcomingHigh.length === 0;

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
      className={`rounded-xl border p-3.5 flex flex-col gap-2 ${
        passed ? "border-emerald-500/25 bg-emerald-500/5" : "border-red-500/30 bg-red-500/5"
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <div className={`w-8 h-8 rounded-full flex items-center justify-center text-base ${
            passed ? "bg-emerald-500/20" : "bg-red-500/20"
          }`}>
            📰
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-white/90">فلتر الأخبار</span>
              <span className={`text-xs ${passed ? "text-emerald-400" : "text-red-400"}`}>
                {passed ? "✅" : "⚠️"}
              </span>
            </div>
            <p className="text-xs text-white/55">
              {passed
                ? news.length === 0
                  ? "لا توجد أخبار عالية التأثير هذا الأسبوع"
                  : "لا توجد أخبار عالية التأثير خلال 3 ساعات القادمة"
                : `⚠️ ${upcomingHigh.length} خبر عالي التأثير خلال 3 ساعات — ارفع المخاطرة`
              }
            </p>
          </div>
        </div>
        {news.length > 0 && (
          <button onClick={() => setExpanded(!expanded)} className="text-white/30 hover:text-white/60 transition-colors">
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>

      {/* Filter status pills */}
      <div className="flex gap-1.5">
        <span className={`text-xs px-1.5 py-0.5 rounded ${
          passed ? "bg-emerald-500/20 text-emerald-400" : "bg-white/5 text-white/25 line-through"
        }`}>شراء</span>
        <span className={`text-xs px-1.5 py-0.5 rounded ${
          passed ? "bg-red-500/20 text-red-400" : "bg-white/5 text-white/25 line-through"
        }`}>بيع</span>
      </div>

      <AnimatePresence>
        {expanded && news.length > 0 && (
          <motion.div initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }} className="overflow-hidden">
            <div className="space-y-1.5 pt-1 border-t border-white/10">
              {news.slice(0, 5).map((item, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span>{item.impact === "High" ? "🔴" : "🟡"}</span>
                  <span className="font-bold text-white/70 shrink-0">{item.currency}</span>
                  <span className="text-white/60 truncate">{item.title}</span>
                  <span className="text-white/35 shrink-0">{item.date} {item.time}</span>
                </div>
              ))}
              {news.length > 5 && (
                <div className="text-[10px] text-white/30">+{news.length - 5} أحداث أخرى</div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ─── Strategy Panel ────────────────────────────────────────────────────
function StrategyPanel({ signals }: { signals: StrategySignal[] }) {
  const buys     = signals.filter(s => s.signal === "BUY").length;
  const sells    = signals.filter(s => s.signal === "SELL").length;
  const neutrals = signals.filter(s => s.signal === "NEUTRAL").length;
  const consensus: "BUY" | "SELL" | "HOLD" = buys > sells ? "BUY" : sells > buys ? "SELL" : "HOLD";
  const nonNeutral = signals.filter(s => s.signal !== "NEUTRAL");
  const avgStr   = nonNeutral.length ? Math.round(nonNeutral.reduce((a, s) => a + s.strength, 0) / nonNeutral.length) : 0;

  return (
    <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
      className="rounded-2xl border border-white/10 bg-white/5 backdrop-blur p-5 space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Target className="w-5 h-5 text-violet-400" />
          <h3 className="font-bold text-base text-white">إشارات الاستراتيجيات</h3>
          <span className="text-xs text-white/40">(10 استراتيجيات)</span>
        </div>
        <div className="flex items-center gap-2 text-sm flex-wrap">
          <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-medium">{buys} شراء</span>
          <span className="px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 font-medium">{sells} بيع</span>
          <span className="px-2 py-0.5 rounded-full bg-white/10 text-white/60 border border-white/10 font-medium">{neutrals} محايد</span>
          {nonNeutral.length > 0 && (
            <span className="px-2 py-0.5 rounded-full bg-violet-500/20 text-violet-300 border border-violet-500/30 font-medium">قوة {avgStr}%</span>
          )}
        </div>
      </div>

      <div className="flex items-center gap-3">
        <span className="text-xs text-white/50 shrink-0">هابط</span>
        <div className="flex-1 h-2 bg-white/10 rounded-full overflow-hidden flex">
          <motion.div initial={{ width: 0 }} animate={{ width: `${sells / signals.length * 100}%` }}
            transition={{ duration: 0.8 }} className="h-full bg-red-500 rounded-l-full" />
          <motion.div initial={{ width: 0 }} animate={{ width: `${neutrals / signals.length * 100}%` }}
            transition={{ duration: 0.8, delay: 0.1 }} className="h-full bg-white/20" />
          <motion.div initial={{ width: 0 }} animate={{ width: `${buys / signals.length * 100}%` }}
            transition={{ duration: 0.8, delay: 0.2 }} className="h-full bg-emerald-500 rounded-r-full" />
        </div>
        <span className="text-xs text-white/50 shrink-0">صاعد</span>
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${
          consensus === "BUY" ? "bg-emerald-500/20 text-emerald-400" :
          consensus === "SELL" ? "bg-red-500/20 text-red-400" :
          "bg-amber-500/20 text-amber-400"
        }`}>
          {consensus === "BUY" ? "توافق: شراء" : consensus === "SELL" ? "توافق: بيع" : "توافق: محايد"}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {signals.map((s, i) => (
          <motion.div key={s.id} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.04 + 0.15 }}
            className={`rounded-xl border p-3 space-y-2 ${
              s.signal === "BUY"  ? "border-emerald-500/30 bg-emerald-500/5" :
              s.signal === "SELL" ? "border-red-500/30 bg-red-500/5" :
              "border-white/10 bg-white/3"
            }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="text-base">{s.emoji}</span>
                <span className="text-xs font-semibold text-white/90">{s.name}</span>
              </div>
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${
                s.signal === "BUY"  ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" :
                s.signal === "SELL" ? "bg-red-500/20 text-red-400 border-red-500/30" :
                "bg-white/10 text-white/50 border-white/10"
              }`}>
                {s.signal === "BUY" ? "🟢" : s.signal === "SELL" ? "🔴" : "🟡"}
                {s.signal === "BUY" ? " شراء" : s.signal === "SELL" ? " بيع" : " محايد"}
              </span>
            </div>
            {s.signal !== "NEUTRAL" && (
              <div className="space-y-1">
                <div className="flex justify-between text-[10px] text-white/40">
                  <span>قوة</span>
                  <span className="font-medium text-white/70">{s.strength}%</span>
                </div>
                <div className="w-full bg-white/10 rounded-full h-1 overflow-hidden">
                  <motion.div initial={{ width: 0 }} animate={{ width: `${s.strength}%` }}
                    transition={{ duration: 0.6, delay: i * 0.04 + 0.2 }}
                    className={`h-full rounded-full ${s.signal === "BUY" ? "bg-emerald-500" : "bg-red-500"}`} />
                </div>
              </div>
            )}
            <p className="text-[10px] text-white/50 leading-relaxed">{s.desc}</p>
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}

// ─── Filter Panel (with economic news integrated) ─────────────────────
function FilterPanel({ filters, news }: { filters: FilterResult[]; news: EconomicNewsItem[] }) {
  const passed = filters.filter(f => f.passed).length;
  return (
    <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
      className="rounded-2xl border border-white/10 bg-white/5 backdrop-blur p-5 space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-blue-400" />
          <h3 className="font-bold text-base text-white">فلاتر التأكيد</h3>
          <span className="text-xs text-white/40">(4 فلاتر تقنية + فلتر الأخبار)</span>
        </div>
        <span className={`text-xs font-bold px-3 py-1 rounded-full border ${
          passed === filters.length ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" :
          passed >= 2 ? "bg-amber-500/20 text-amber-400 border-amber-500/30" :
          "bg-red-500/20 text-red-400 border-red-500/30"
        }`}>
          {passed}/{filters.length} فلاتر تقنية
        </span>
      </div>

      {/* Technical filters */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {filters.map((f, i) => (
          <motion.div key={f.id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.07 + 0.25 }}
            className={`rounded-xl border p-3.5 flex items-start gap-3 ${
              f.passed ? "border-emerald-500/25 bg-emerald-500/5" : "border-amber-500/25 bg-amber-500/5"
            }`}>
            <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 text-base ${
              f.passed ? "bg-emerald-500/20" : "bg-amber-500/20"
            }`}>
              {f.emoji}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-semibold text-white/90">{f.name}</span>
                <span className={`text-xs ${f.passed ? "text-emerald-400" : "text-amber-400"}`}>
                  {f.passed ? "✅" : "⚠️"}
                </span>
              </div>
              <p className="text-xs text-white/55 leading-relaxed">{f.desc}</p>
              {(f.allowsBuy !== f.allowsSell) && (
                <div className="flex gap-1.5 mt-2">
                  <span className={`text-xs px-1.5 py-0.5 rounded ${f.allowsBuy ? "bg-emerald-500/20 text-emerald-400" : "bg-white/5 text-white/25 line-through"}`}>شراء</span>
                  <span className={`text-xs px-1.5 py-0.5 rounded ${f.allowsSell ? "bg-red-500/20 text-red-400" : "bg-white/5 text-white/25 line-through"}`}>بيع</span>
                </div>
              )}
            </div>
          </motion.div>
        ))}

        {/* Economic News as a filter card — integrated here */}
        <NewsFilterCard news={news} />
      </div>
    </motion.div>
  );
}

// ─── Signal Badge ─────────────────────────────────────────────────────
function SignalBadge({ signal, size = "md" }: { signal: "BUY" | "SELL" | "HOLD"; size?: "sm" | "md" | "lg" }) {
  const config = {
    BUY:  { color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40", icon: <TrendingUp  className={size === "lg" ? "w-5 h-5" : "w-3.5 h-3.5"} />, label: "شراء" },
    SELL: { color: "bg-red-500/20    text-red-400    border-red-500/40",    icon: <TrendingDown className={size === "lg" ? "w-5 h-5" : "w-3.5 h-3.5"} />, label: "بيع"   },
    HOLD: { color: "bg-amber-500/20  text-amber-400  border-amber-500/40",  icon: <Minus        className={size === "lg" ? "w-5 h-5" : "w-3.5 h-3.5"} />, label: "انتظار" },
  }[signal];
  const sizes = { sm: "text-xs px-2 py-0.5 gap-1", md: "text-sm px-2.5 py-1 gap-1.5", lg: "text-base px-4 py-2 gap-2 font-bold" };
  return (
    <span className={`inline-flex items-center rounded-full border font-medium ${config.color} ${sizes[size]}`}>
      {config.icon} {config.label}
    </span>
  );
}

// ─── Confidence Bar ───────────────────────────────────────────────────
function ConfidenceBar({ value, signal }: { value: number; signal: "BUY" | "SELL" | "HOLD" }) {
  const color = signal === "BUY" ? "bg-emerald-500" : signal === "SELL" ? "bg-red-500" : "bg-amber-500";
  return (
    <div className="w-full bg-secondary rounded-full h-1.5 overflow-hidden">
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${value}%` }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        className={`h-full rounded-full ${color}`}
      />
    </div>
  );
}

// ─── AI Model Card ────────────────────────────────────────────────────
function ModelCard({ provider, result, isLoading }: {
  provider: string;
  result?: AnalysisResult;
  isLoading: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const PLACEHOLDERS: Record<string, { name: string; icon: string; color: string }> = {
    claude:    { name: "Claude Opus",   icon: "🟣", color: "#7C3AED" },
    gpt4:      { name: "Claude Haiku",  icon: "🟡", color: "#F59E0B" },
    gemini:    { name: "Gemini 2.5 Flash", icon: "🔵", color: "#3B82F6" },
    geminiPro: { name: "Gemini 2.5 Pro",   icon: "💎", color: "#06B6D4" },
    deepseek:  { name: "DeepSeek R1",   icon: "⚡", color: "#F59E0B" },
  };
  const ph = PLACEHOLDERS[provider] ?? PLACEHOLDERS.claude;
  const name = result?.providerName || ph.name;
  const icon = result?.icon || ph.icon;
  const color = result?.color || ph.color;
  const isAvailable = result ? result.available !== false : true;
  const hasError = result !== undefined && !isAvailable;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="bg-card border border-border rounded-2xl p-4 flex flex-col gap-3"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-xl flex items-center justify-center text-base"
            style={{ background: `${color}20`, border: `1px solid ${color}40` }}>
            {icon}
          </div>
          <div>
            <div className="font-bold text-sm">{name}</div>
            {result && !isLoading && (
              <div className="text-xs text-muted-foreground">
                {(result.duration / 1000).toFixed(1)}s
              </div>
            )}
          </div>
        </div>
        {isLoading ? (
          <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
        ) : hasError ? (
          <span className="text-xs text-red-400 flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5" /> غير متاح
          </span>
        ) : result ? (
          <SignalBadge signal={result.signal} size="md" />
        ) : null}
      </div>

      {isLoading && (
        <div className="space-y-2">
          {[70, 50, 90].map((w, i) => (
            <div key={i} className="h-3 bg-secondary rounded animate-pulse" style={{ width: `${w}%` }} />
          ))}
        </div>
      )}

      {hasError && !isLoading && (
        <div className="text-xs text-muted-foreground bg-secondary/50 rounded-xl p-3 flex items-start gap-2">
          <XCircle className="w-3.5 h-3.5 mt-0.5 shrink-0 text-red-400" />
          <span>النموذج غير متاح حالياً.</span>
        </div>
      )}

      {result && isAvailable && !isLoading && (
        <div className="space-y-3">
          <div className="space-y-1">
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>مستوى الثقة</span>
              <span className="font-medium text-foreground">{result.confidence}%</span>
            </div>
            <ConfidenceBar value={result.confidence} signal={result.signal} />
          </div>

          <div className="flex items-center gap-2 text-xs">
            <Shield className="w-3 h-3 text-muted-foreground" />
            <span className="text-muted-foreground">المخاطرة:</span>
            <span className={result.risk === "LOW" ? "text-emerald-400" : result.risk === "HIGH" ? "text-red-400" : "text-amber-400"}>
              {result.risk === "LOW" ? "منخفضة" : result.risk === "HIGH" ? "عالية" : "متوسطة"}
            </span>
          </div>

          <div className="grid grid-cols-3 gap-2 text-xs">
            <div className="bg-secondary/60 rounded-lg p-2 text-center">
              <div className="text-muted-foreground mb-0.5 flex items-center justify-center gap-1">
                <Target className="w-2.5 h-2.5" /> دخول
              </div>
              <div className="font-mono font-medium text-foreground truncate">{result.entryZone}</div>
            </div>
            <div className="bg-red-500/10 rounded-lg p-2 text-center">
              <div className="text-muted-foreground mb-0.5 flex items-center justify-center gap-1">
                <StopCircle className="w-2.5 h-2.5 text-red-400" /> وقف
              </div>
              <div className="font-mono font-medium text-red-400 truncate">{result.stopLoss}</div>
            </div>
            <div className="bg-emerald-500/10 rounded-lg p-2 text-center">
              <div className="text-muted-foreground mb-0.5 flex items-center justify-center gap-1">
                <TrendingUp className="w-2.5 h-2.5 text-emerald-400" /> هدف
              </div>
              <div className="font-mono font-medium text-emerald-400 truncate">{result.takeProfit}</div>
            </div>
          </div>

          <button
            onClick={() => setExpanded(!expanded)}
            className="w-full text-left text-xs text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
          >
            {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            {expanded ? "إخفاء التحليل" : "عرض التحليل"}
          </button>
          <AnimatePresence>
            {expanded && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden"
              >
                <div className="text-xs text-muted-foreground bg-secondary/40 rounded-xl p-3 leading-relaxed">
                  {result.reasoning}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </motion.div>
  );
}

// ─── Consensus Banner ─────────────────────────────────────────────────
function ConsensusBanner({ results, news }: { results: AnalysisResult[]; news: EconomicNewsItem[] }) {
  const available = results.filter(r => r.available && !r.error);
  if (available.length === 0) return null;
  const buys  = available.filter(r => r.signal === "BUY").length;
  const sells = available.filter(r => r.signal === "SELL").length;
  const holds = available.filter(r => r.signal === "HOLD").length;
  const dominant = buys >= sells && buys >= holds ? "BUY" : sells >= buys && sells >= holds ? "SELL" : "HOLD";
  const avgConf = Math.round(available.reduce((s, r) => s + r.confidence, 0) / available.length);

  // Check for high-impact news warning
  const now = new Date();
  const hasUrgentNews = news.some(e => {
    if (!e.date || !e.time) return false;
    try {
      const t = new Date(e.date + " " + (e.time || "").replace("am", " AM").replace("pm", " PM"));
      const diffH = (t.getTime() - now.getTime()) / 3600000;
      return e.impact === "High" && diffH >= -0.5 && diffH <= 2;
    } catch { return false; }
  });

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="bg-card border border-border rounded-2xl p-5 flex flex-col sm:flex-row items-center justify-between gap-4"
    >
      <div className="flex items-center gap-4 flex-wrap justify-center sm:justify-start">
        <div className="text-center">
          <div className="text-xs text-muted-foreground mb-2">إجماع الذكاء الاصطناعي</div>
          <SignalBadge signal={dominant} size="lg" />
        </div>
        <div className="h-12 w-px bg-border hidden sm:block" />
        <div className="flex gap-4 text-sm">
          <div className="text-center">
            <div className="text-emerald-400 font-bold text-lg">{buys}</div>
            <div className="text-muted-foreground text-xs">شراء</div>
          </div>
          <div className="text-center">
            <div className="text-red-400 font-bold text-lg">{sells}</div>
            <div className="text-muted-foreground text-xs">بيع</div>
          </div>
          <div className="text-center">
            <div className="text-amber-400 font-bold text-lg">{holds}</div>
            <div className="text-muted-foreground text-xs">انتظار</div>
          </div>
        </div>
      </div>

      <div className="text-center sm:text-right">
        <div className="text-xs text-muted-foreground mb-1">متوسط الثقة</div>
        <div className="text-2xl font-bold">{avgConf}%</div>
        <div className="flex items-center gap-1 text-xs text-muted-foreground mt-1">
          <Trophy className="w-3 h-3 text-amber-400" />
          {available.length}/{results.length} نماذج
        </div>
        {hasUrgentNews && (
          <div className="mt-2 text-xs text-red-400 flex items-center gap-1">
            <Newspaper className="w-3 h-3" /> خبر عالي التأثير قريب — تحذير
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ─── Indicators Panel ─────────────────────────────────────────────────
function IndicatorsPanel({ data }: { data: TradingData }) {
  const { indicators, currentPrice, pair } = data;
  const decimals = pair === "BTCUSD" ? 1 : pair === "XAUUSD" ? 2 : pair === "XAGUSD" ? 3 : pair.includes("JPY") ? 3 : 5;
  const rsiColor = indicators.rsi > 70 ? "text-red-400" : indicators.rsi < 30 ? "text-emerald-400" : "text-amber-400";
  const rsiLabel = indicators.rsi > 70 ? "ذروة شراء" : indicators.rsi < 30 ? "ذروة بيع" : "محايد";

  const stoch = (indicators as any).stoch;
  const williamsR = (indicators as any).williamsR;
  const adx = (indicators as any).adx;
  const pivots = (indicators as any).pivots;

  const items = [
    { label: "السعر الحالي", value: currentPrice.toFixed(decimals), highlight: true },
    { label: "RSI (14)", value: `${indicators.rsi.toFixed(1)} — ${rsiLabel}`, color: rsiColor },
    { label: "SMA 20",   value: indicators.sma20.toFixed(decimals), color: currentPrice > indicators.sma20 ? "text-emerald-400" : "text-red-400" },
    { label: "SMA 50",   value: indicators.sma50.toFixed(decimals), color: currentPrice > indicators.sma50 ? "text-emerald-400" : "text-red-400" },
    ...(indicators.sma200 ? [{ label: "SMA 200", value: indicators.sma200.toFixed(decimals), color: currentPrice > indicators.sma200 ? "text-emerald-400" : "text-red-400" }] : []),
    { label: "MACD",      value: indicators.macd.macd.toFixed(5), color: indicators.macd.macd > 0 ? "text-emerald-400" : "text-red-400" },
    { label: "BB العلوي", value: indicators.bb.upper.toFixed(decimals) },
    { label: "BB السفلي", value: indicators.bb.lower.toFixed(decimals) },
    { label: "ATR (14)", value: indicators.atr.toFixed(decimals) },
    ...(stoch ? [{ label: "Stochastic", value: `%K=${stoch.k.toFixed(1)} %D=${stoch.d.toFixed(1)}`, color: stoch.k > 80 ? "text-red-400" : stoch.k < 20 ? "text-emerald-400" : "text-foreground" }] : []),
    ...(williamsR !== undefined ? [{ label: "Williams %R", value: williamsR.toFixed(1), color: williamsR > -20 ? "text-red-400" : williamsR < -80 ? "text-emerald-400" : "text-foreground" }] : []),
    ...(adx ? [{ label: "ADX", value: `${adx.adx.toFixed(1)} ${adx.adx > 25 ? "📈" : "➡️"}`, color: adx.adx > 25 ? "text-emerald-400" : "text-muted-foreground" }] : []),
    ...(pivots ? [
      { label: "Pivot", value: pivots.pivot.toFixed(decimals), color: currentPrice > pivots.pivot ? "text-emerald-400" : "text-red-400" },
      { label: "R1 / S1", value: `${pivots.r1.toFixed(decimals)} / ${pivots.s1.toFixed(decimals)}` },
    ] : []),
  ];

  return (
    <div className="bg-card border border-border rounded-2xl p-4 space-y-2">
      <div className="flex items-center gap-2 mb-3">
        <Activity className="w-4 h-4 text-primary" />
        <span className="font-bold text-sm">المؤشرات التقنية</span>
      </div>
      {items.map((item, i) => (
        <div key={i} className="flex items-center justify-between text-sm py-1 border-b border-border/40 last:border-0">
          <span className="text-muted-foreground">{item.label}</span>
          <span className={`font-mono font-medium ${item.color || "text-foreground"} ${item.highlight ? "text-base font-bold text-primary" : ""}`}>
            {item.value}
          </span>
        </div>
      ))}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────
export default function TradingAnalysis() {
  const { isAuthenticated, loading: authLoading } = useAuth();
  const [selectedPair, setSelectedPair] = useState("EURUSD");
  const [selectedTf, setSelectedTf] = useState("15min");
  const [hasRun, setHasRun] = useState(false);
  const [tradingData, setTradingData] = useState<TradingData | null>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const currentPair = PAIRS.find(p => p.id === selectedPair)!;
  const currentTf   = TIMEFRAMES.find(t => t.id === selectedTf)!;
  const tvSymbol    = encodeURIComponent(currentPair.tv);
  const chartUrl    = `https://www.tradingview.com/widgetembed/?frameElementId=hayo_chart&symbol=${tvSymbol}&interval=${currentTf.tv}&hidesidetoolbar=0&symboledit=0&saveimage=0&theme=dark&style=1&timezone=exchange&withdateranges=1&locale=ar&hide_legend=0`;

  // Telegram send
  const telegramMut = trpc.tradingAnalysis.sendToTelegram.useMutation({
    onSuccess: () => toast.success("تم إرسال التحليل لـ Telegram! ✅"),
    onError: (err) => toast.error(`فشل الإرسال: ${err.message}`),
  });

  // Auto-Signal: Multi-timeframe confluence
  // ─── OANDA Auto-Execute ─────────────────────────────────────────
  const [oandaToken, setOandaToken] = useState(() => localStorage.getItem("hayo-oanda-token") || "");
  const [oandaAccount, setOandaAccount] = useState(() => localStorage.getItem("hayo-oanda-account") || "");
  const [oandaEnv, setOandaEnv] = useState<"practice" | "live">(() => (localStorage.getItem("hayo-oanda-env") as any) || "practice");
  const [autoExecuteEnabled, setAutoExecuteEnabled] = useState(false);
  const [riskPercent, setRiskPercent] = useState(1);
  const [showOandaSetup, setShowOandaSetup] = useState(false);

  // Save OANDA credentials to localStorage
  const saveOandaCredentials = () => {
    localStorage.setItem("hayo-oanda-token", oandaToken);
    localStorage.setItem("hayo-oanda-account", oandaAccount);
    localStorage.setItem("hayo-oanda-env", oandaEnv);
    toast.success("✅ تم حفظ إعدادات OANDA");
    setShowOandaSetup(false);
  };

  const oandaConnected = !!(oandaToken && oandaAccount);

  const autoExecuteMut = trpc.trading.autoExecute.useMutation({
    onSuccess: (data: any) => {
      if (data.success) {
        toast.success(`✅ تم تنفيذ الصفقة! السعر: ${data.price} | ${data.riskInfo}`);
      } else {
        toast.error(`❌ فشل التنفيذ: ${data.error}`);
      }
    },
    onError: (err: any) => toast.error(`خطأ: ${err.message}`),
  });

  const autoSignalMut = trpc.tradingAnalysis.autoSignal.useMutation({
    onSuccess: (data) => {
      if (data.signalsFound > 0) {
        toast.success(`🚨 ${data.signalsFound} إشارة تقاطع 3 فريمات — تم الإرسال لـ Telegram!`);

        // Auto-execute on OANDA if enabled
        if (autoExecuteEnabled && oandaConnected) {
          for (const sig of data.confirmedSignals) {
            autoExecuteMut.mutate({
              apiToken: oandaToken,
              accountId: oandaAccount,
              environment: oandaEnv,
              pair: sig.pair,
              direction: sig.signal,
              confidence: sig.confidence,
              stopLoss: parseFloat(sig.stopLoss) || undefined,
              takeProfit: parseFloat(sig.takeProfit) || undefined,
              riskPercent,
            });
          }
          toast.info(`🤖 جاري تنفيذ ${data.signalsFound} صفقة تلقائياً على OANDA...`);
        }
      } else {
        toast.info(`✅ تم فحص ${data.totalPairsScanned} أزواج — لا تقاطع حالياً`);
      }
    },
    onError: (err) => toast.error(`خطأ: ${err.message}`),
  });

  const analyzeMutation = trpc.tradingAnalysis.analyzeMarket.useMutation({
    onSuccess: (data: any) => {
      setTradingData(data as unknown as TradingData);
      const ok = (data as unknown as TradingData).results.filter((r: AnalysisResult) => r.available && !r.error).length;
      toast.success(`اكتمل التحليل! ${ok}/3 نماذج أجابت`);
    },
    onError: (err: any) => {
      setHasRun(false);
      if (err.data?.code === "PRECONDITION_FAILED") {
        toast.error("أضف TWELVE_DATA_API_KEY في إعدادات المنصة أولاً");
      } else if (err.data?.code === "TOO_MANY_REQUESTS") {
        toast.error("نفدت نقاطك اليومية.");
      } else {
        toast.error(`خطأ: ${err.message}`);
      }
    },
  });

  const handleAnalyze = (pair = selectedPair, tf = selectedTf) => {
    setSelectedPair(pair);
    setSelectedTf(tf);
    setTradingData(null);
    setHasRun(true);
    analyzeMutation.mutate({ pair: pair as any, timeframe: tf as any });
  };

  const handleSendToTelegram = () => {
    if (!tradingData) return;
    const available = tradingData.results.filter(r => r.available && !r.error);
    const buys  = available.filter(r => r.signal === "BUY").length;
    const sells = available.filter(r => r.signal === "SELL").length;
    const holds = available.filter(r => r.signal === "HOLD").length;
    const dominant = buys >= sells && buys >= holds ? "BUY" : sells >= buys && sells >= holds ? "SELL" : "HOLD";
    const avgConf = Math.round(available.reduce((s, r) => s + r.confidence, 0) / (available.length || 1));

    telegramMut.mutate({
      pair: tradingData.pair,
      timeframe: tradingData.timeframe,
      price: tradingData.currentPrice,
      signal: dominant,
      confidence: avgConf,
      indicators: {
        rsi: tradingData.indicators.rsi,
        macd: tradingData.indicators.macd,
        sma20: tradingData.indicators.sma20,
        sma50: tradingData.indicators.sma50,
        sma200: tradingData.indicators.sma200 ?? null,
        bb: tradingData.indicators.bb,
        atr: tradingData.indicators.atr,
        ...(tradingData.indicators as any).stoch && { stoch: (tradingData.indicators as any).stoch },
        ...(tradingData.indicators as any).williamsR !== undefined && { williamsR: (tradingData.indicators as any).williamsR },
        ...(tradingData.indicators as any).adx && { adx: (tradingData.indicators as any).adx },
        ...(tradingData.indicators as any).pivots && { pivots: (tradingData.indicators as any).pivots },
      },
      strategySignals: tradingData.strategySignals.map(s => ({
        name: s.name,
        signal: s.signal,
        strength: s.strength,
        emoji: s.emoji,
      })),
      filterResults: tradingData.filterResults.map(f => ({
        name: f.name,
        passed: f.passed,
        desc: f.desc,
        emoji: f.emoji,
      })),
      aiResults: tradingData.results.map(r => ({
        name: r.providerName,
        icon: r.icon,
        signal: r.signal,
        confidence: r.confidence,
        reasoning: r.reasoning,
        entryZone: r.entryZone,
        stopLoss: r.stopLoss,
        takeProfit: r.takeProfit,
        risk: r.risk,
        available: r.available,
      })),
    });
  };

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
          <BarChart3 className="w-16 h-16 mx-auto text-primary opacity-60" />
          <h2 className="text-2xl font-bold">تحليل الأسواق</h2>
          <p className="text-muted-foreground">سجّل دخولك للوصول إلى محلل الأسواق المالية</p>
          <Button asChild className="w-full"><a href={getLoginUrl()}>تسجيل الدخول</a></Button>
        </div>
      </div>
    );
  }

  const analysisNews = tradingData?.economicNews ?? [];

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col" dir="rtl">
      {/* Top Bar */}
      <header className="h-12 bg-card border-b border-border flex items-center justify-between px-4 shrink-0">
        <div className="flex items-center gap-3">
          <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">
            <Home className="w-4 h-4" />
          </Link>
          <div className="w-px h-5 bg-border" />
          <BarChart3 className="w-5 h-5 text-emerald-400" />
          <span className="font-bold text-sm">محلل الأسواق المالية</span>
          <span className="text-xs bg-emerald-400/10 text-emerald-400 px-2 py-0.5 rounded-full">AI × 3</span>
          <span className="text-xs bg-violet-400/10 text-violet-400 px-2 py-0.5 rounded-full">10 استراتيجيات</span>
          <span className="text-xs bg-blue-400/10 text-blue-400 px-2 py-0.5 rounded-full">5 فلاتر</span>
        </div>
        <div className="text-xs text-muted-foreground hidden sm:flex items-center gap-1">
          <AlertTriangle className="w-3 h-3 text-amber-400" />
          تحليل تعليمي وليس نصيحة مالية
        </div>
      </header>

      <div className="flex-1 flex flex-col max-w-7xl w-full mx-auto px-3 sm:px-6 py-4 gap-4">

        {/* Pair & Timeframe Selector */}
        <div className="bg-card border border-border rounded-2xl p-4 space-y-4">
          <div>
            <div className="text-xs text-muted-foreground mb-2 font-medium">اختر الزوج</div>
            <div className="flex flex-wrap gap-2">
              {PAIRS.map(pair => (
                <button
                  key={pair.id}
                  onClick={() => setSelectedPair(pair.id)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-xl border text-sm font-medium transition-all ${
                    selectedPair === pair.id
                      ? "bg-primary text-primary-foreground border-primary shadow-sm scale-105"
                      : "bg-secondary/50 border-border hover:bg-secondary text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <span className="text-base">{pair.flag}</span>
                  <span>{pair.label}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <div className="text-xs text-muted-foreground font-medium shrink-0">الإطار الزمني:</div>
            <div className="flex gap-2">
              {TIMEFRAMES.map(tf => (
                <button
                  key={tf.id}
                  onClick={() => setSelectedTf(tf.id)}
                  className={`px-3 py-1.5 rounded-lg border text-sm font-bold transition-all flex items-center gap-1 ${
                    selectedTf === tf.id
                      ? "bg-emerald-500 text-white border-emerald-500 shadow-sm"
                      : "bg-secondary/50 border-border hover:bg-secondary text-muted-foreground"
                  }`}
                >
                  <span className="text-xs">{tf.icon}</span>{tf.label}
                </button>
              ))}
            </div>
            <div className="flex-1" />
            <Button
              onClick={() => handleAnalyze()}
              disabled={analyzeMutation.isPending}
              className="gap-2 bg-emerald-600 hover:bg-emerald-700 text-white font-bold shrink-0"
            >
              {analyzeMutation.isPending ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> جاري التحليل...</>
              ) : (
                <><Zap className="w-4 h-4" /> تحليل الآن</>
              )}
            </Button>
          </div>
        </div>

        {/* Quick Scan with auto-refresh */}
        <QuickScanPanel onSelectPair={(pair, tf) => handleAnalyze(pair, tf)} />

        {/* Convergence Panel (التطابق) */}
        <ConvergencePanel onSelectPair={(pair, tf) => handleAnalyze(pair, tf)} />

        {/* Main Content */}
        <div className="flex flex-col lg:flex-row gap-4 flex-1">
          {/* Chart */}
          <div className="flex-1 min-h-[380px] lg:min-h-0 bg-card border border-border rounded-2xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-card/80 backdrop-blur-sm">
              <span className="text-base">{currentPair.flag}</span>
              <span className="font-bold text-sm">{currentPair.label}</span>
              <span className="text-xs text-muted-foreground">{currentPair.desc}</span>
              <div className="flex-1" />
              <span className="text-xs bg-secondary px-2 py-0.5 rounded-full font-bold">{currentTf.label}</span>
            </div>
            <iframe
              ref={iframeRef}
              src={chartUrl}
              className="w-full h-[380px] lg:h-full border-0"
              allowTransparency={true}
              allow="fullscreen"
              title={`${currentPair.label} Chart`}
            />
          </div>

          {/* Right Panel */}
          <div className="w-full lg:w-72 flex flex-col gap-4">
            {!hasRun && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-card border border-border rounded-2xl p-5 text-center space-y-3"
              >
                <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-emerald-400/10 mb-1">
                  <BarChart3 className="w-7 h-7 text-emerald-400" />
                </div>
                <h2 className="font-bold text-base">محلل الأسواق بـ AI × 3</h2>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  10 استراتيجيات + 5 فلاتر (4 تقنية + الأخبار) + 3 نماذج AI + إشارات تلقائية
                </p>
                <div className="grid grid-cols-3 gap-1.5 text-xs">
                  <div className="bg-violet-500/10 border border-violet-500/20 rounded-lg p-1.5 text-violet-400 text-center">🟣 Claude Opus 4</div>
                  <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-lg p-1.5 text-cyan-400 text-center">💎 Gemini Pro</div>
                  <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-1.5 text-yellow-400 text-center">⚡ DeepSeek R1</div>
                </div>
                <div className="bg-amber-400/10 rounded-xl p-3 text-xs text-amber-400 text-right">
                  ⚠️ للأغراض التعليمية فقط.
                </div>
              </motion.div>
            )}

            {tradingData && !analyzeMutation.isPending && (
              <IndicatorsPanel data={tradingData} />
            )}

            {analyzeMutation.isPending && (
              <div className="bg-card border border-border rounded-2xl p-5 flex flex-col items-center gap-3">
                <Loader2 className="w-8 h-8 animate-spin text-emerald-400" />
                <div className="text-sm font-medium">يجري التحليل...</div>
                <div className="text-xs text-muted-foreground text-center">
                  10 استراتيجيات + 5 فلاتر + 3 نماذج AI + أخبار اقتصادية
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Analysis Results */}
        <AnimatePresence>
          {hasRun && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-4"
            >
              {tradingData && !analyzeMutation.isPending && (
                <ConsensusBanner results={tradingData.results} news={analysisNews} />
              )}

              {tradingData && !analyzeMutation.isPending && tradingData.strategySignals?.length > 0 && (
                <StrategyPanel signals={tradingData.strategySignals} />
              )}

              {/* Filters + Economic News integrated together */}
              {tradingData && !analyzeMutation.isPending && tradingData.filterResults?.length > 0 && (
                <FilterPanel filters={tradingData.filterResults} news={analysisNews} />
              )}

              {/* 3 AI Model Cards — Claude Opus 4 + Gemini Pro + DeepSeek */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {PROVIDER_ORDER.map(provider => {
                  const result = tradingData?.results.find(r => r.provider === provider);
                  return (
                    <ModelCard
                      key={provider}
                      provider={provider}
                      result={result}
                      isLoading={analyzeMutation.isPending && !result}
                    />
                  );
                })}
              </div>

              {/* Action buttons */}
              {tradingData && !analyzeMutation.isPending && (
                <>
                <div className="flex justify-center gap-3 flex-wrap">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleAnalyze()}
                    className="gap-2 text-xs"
                  >
                    <RefreshCw className="w-3 h-3" /> إعادة التحليل
                  </Button>
                  <Button
                    size="sm"
                    onClick={handleSendToTelegram}
                    disabled={telegramMut.isPending}
                    className="gap-2 text-xs bg-blue-600 hover:bg-blue-700 text-white"
                  >
                    {telegramMut.isPending
                      ? <><Loader2 className="w-3 h-3 animate-spin" /> إرسال...</>
                      : <><Send className="w-3 h-3" /> إرسال لـ Telegram</>
                    }
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => autoSignalMut.mutate({ pairs: PAIRS.map(p => p.id) })}
                    disabled={autoSignalMut.isPending}
                    className="gap-2 text-xs bg-gradient-to-r from-amber-600 to-red-600 hover:from-amber-500 hover:to-red-500 text-white"
                  >
                    {autoSignalMut.isPending
                      ? <><Loader2 className="w-3 h-3 animate-spin" /> فحص تلقائي...</>
                      : <><Zap className="w-3 h-3" /> إشارات تلقائية (3 فريمات)</>
                    }
                  </Button>

                  {/* OANDA Auto-Execute Toggle */}
                  <Button
                    size="sm"
                    variant={autoExecuteEnabled ? "default" : "outline"}
                    onClick={() => {
                      if (!oandaConnected) { setShowOandaSetup(true); return; }
                      setAutoExecuteEnabled(!autoExecuteEnabled);
                      toast.info(autoExecuteEnabled ? "⏸️ تم إيقاف التنفيذ التلقائي" : "▶️ تم تفعيل التنفيذ التلقائي على OANDA");
                    }}
                    className={`gap-2 text-xs ${autoExecuteEnabled ? "bg-emerald-600 hover:bg-emerald-700" : "border-cyan-500/30 text-cyan-400"}`}
                  >
                    {autoExecuteEnabled ? "🟢 OANDA: مفعّل" : "⚡ ربط OANDA"}
                  </Button>

                  <Button size="sm" variant="ghost" onClick={() => setShowOandaSetup(!showOandaSetup)} className="text-xs gap-1 text-muted-foreground">
                    ⚙️
                  </Button>
                </div>

                {/* OANDA Setup Panel */}
                {showOandaSetup && (
                  <div className="bg-card border border-cyan-500/20 rounded-xl p-4 space-y-3 mt-3">
                    <div className="flex items-center gap-2 text-sm font-bold text-cyan-400">
                      ⚡ إعداد OANDA للتنفيذ التلقائي
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <label className="text-[10px] text-muted-foreground">API Token</label>
                        <input value={oandaToken} onChange={e => setOandaToken(e.target.value)} type="password" placeholder="OANDA API Token..." className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs font-mono" dir="ltr" />
                      </div>
                      <div className="space-y-1">
                        <label className="text-[10px] text-muted-foreground">Account ID</label>
                        <input value={oandaAccount} onChange={e => setOandaAccount(e.target.value)} placeholder="001-001-1234567-001" className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs font-mono" dir="ltr" />
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <label className="text-[10px] text-muted-foreground">البيئة</label>
                        <div className="flex gap-2">
                          {(["practice", "live"] as const).map(env => (
                            <button key={env} onClick={() => setOandaEnv(env)} className={`flex-1 px-3 py-1.5 rounded-lg border text-xs ${oandaEnv === env ? "bg-primary/15 border-primary text-primary" : "border-border text-muted-foreground"}`}>
                              {env === "practice" ? "🧪 تجريبي" : "🔴 حقيقي"}
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="space-y-1">
                        <label className="text-[10px] text-muted-foreground">نسبة المخاطرة %</label>
                        <input type="number" value={riskPercent} onChange={e => setRiskPercent(Math.max(0.1, Math.min(5, parseFloat(e.target.value) || 1)))} min={0.1} max={5} step={0.5} className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs" />
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" onClick={saveOandaCredentials} className="flex-1 text-xs bg-cyan-600 hover:bg-cyan-700">حفظ الإعدادات</Button>
                      <Button size="sm" variant="outline" onClick={() => setShowOandaSetup(false)} className="text-xs">إغلاق</Button>
                    </div>
                    {oandaEnv === "live" && (
                      <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-2 text-[10px] text-red-400">
                        ⚠️ أنت في الوضع الحقيقي! الصفقات ستنفذ بأموال حقيقية. تأكد من ضبط نسبة المخاطرة بحذر.
                      </div>
                    )}
                  </div>
                )}
                </>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
