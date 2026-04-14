/**
 * HAYO AI - Telegram Bot Integration Setup
 * Full page for connecting, configuring, and managing Telegram bot
 */

import { useState, useEffect } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { trpc } from "@/lib/trpc";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import {
  ArrowLeft, Bot, Check, CheckCircle2, ChevronDown, ChevronUp,
  Copy, ExternalLink, Eye, EyeOff, Globe, Home, Loader2,
  MessageSquare, Plug, Power, PowerOff, RefreshCw, Send,
  Settings, Shield, Terminal, Trash2, User, Users, Wifi, WifiOff,
  Zap, AlertCircle, Info, HelpCircle,
} from "lucide-react";

const HAYO_LOGO = import.meta.env.VITE_APP_LOGO || "";

function TelegramIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="#26A5E4">
      <path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z" />
    </svg>
  );
}

function BotFatherIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 48 48" className={className}>
      <circle cx="24" cy="24" r="22" fill="#0088cc" />
      <path d="M24 10c-2 0-4 1-5 3l-1 3c-3 1-5 4-5 7 0 1 0 2 .5 3-.5 1-1 3-.5 5s2 3 3 3c1 2 4 4 8 4s7-2 8-4c1 0 2.5-1 3-3s0-4-.5-5c.5-1 .5-2 .5-3 0-3-2-6-5-7l-1-3c-1-2-3-3-5-3z" fill="white" />
      <circle cx="19" cy="22" r="2" fill="#0088cc" />
      <circle cx="29" cy="22" r="2" fill="#0088cc" />
      <path d="M20 28c0 0 2 2 4 2s4-2 4-2" stroke="#0088cc" strokeWidth="1.5" fill="none" strokeLinecap="round" />
    </svg>
  );
}

// ─── Setup Steps Guide ──────────────────────────────────────────────
function SetupGuide({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const [activeStep, setActiveStep] = useState(0);

  const steps = [
    {
      title: "افتح BotFather في Telegram",
      desc: "ابحث عن @BotFather في Telegram أو اضغط على الرابط أدناه",
      action: (
        <a
          href="https://t.me/BotFather"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-4 py-2 bg-[#26A5E4]/20 hover:bg-[#26A5E4]/30 text-[#26A5E4] rounded-lg transition-colors"
        >
          <BotFatherIcon className="w-5 h-5" />
          فتح BotFather
          <ExternalLink className="w-4 h-4" />
        </a>
      ),
    },
    {
      title: "أنشئ بوت جديد",
      desc: 'أرسل الأمر /newbot إلى BotFather واتبع التعليمات. اختر اسماً ومعرّفاً (username) للبوت ينتهي بـ "bot"',
      code: "/newbot",
    },
    {
      title: "انسخ توكن البوت (Bot Token)",
      desc: "بعد إنشاء البوت، سيعطيك BotFather توكن يبدو مثل:",
      code: "123456789:ABCdefGHIjklMNOpqrsTUVwxyz",
    },
    {
      title: "الصق التوكن هنا",
      desc: "الصق التوكن في الحقل أدناه واضغط 'ربط البوت'. سيتم تفعيل Webhook تلقائياً وسيصبح البوت جاهزاً للعمل!",
    },
  ];

  return (
    <div className="bg-card/50 border border-border/50 rounded-2xl p-6 mb-8">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
          <HelpCircle className="w-5 h-5 text-[#26A5E4]" />
          دليل إنشاء البوت
        </h3>
        <Button variant="ghost" size="sm" onClick={onClose}>
          إخفاء
        </Button>
      </div>

      <div className="space-y-4">
        {steps.map((step, i) => (
          <div
            key={i}
            className={`flex gap-4 p-4 rounded-xl transition-all cursor-pointer ${
              activeStep === i
                ? "bg-[#26A5E4]/10 border border-[#26A5E4]/30"
                : "hover:bg-muted/50"
            }`}
            onClick={() => setActiveStep(i)}
          >
            <div
              className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 text-sm font-bold ${
                activeStep === i
                  ? "bg-[#26A5E4] text-white"
                  : "bg-muted text-muted-foreground"
              }`}
            >
              {i + 1}
            </div>
            <div className="flex-1">
              <h4 className="font-medium text-foreground">{step.title}</h4>
              <p className="text-sm text-muted-foreground mt-1">{step.desc}</p>
              {step.code && activeStep === i && (
                <div className="mt-3 bg-background/80 border border-border/50 rounded-lg p-3 font-mono text-sm text-[#26A5E4] flex items-center justify-between" dir="ltr">
                  <span>{step.code}</span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      navigator.clipboard.writeText(step.code!);
                      toast.success("تم النسخ!");
                    }}
                    className="p-1 hover:bg-muted rounded"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
              )}
              {step.action && activeStep === i && (
                <div className="mt-3">{step.action}</div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Connected Bot Dashboard ────────────────────────────────────────
function BotDashboard({
  bot,
  onDisconnect,
  onRefresh,
  disconnecting,
}: {
  bot: any;
  onDisconnect: () => void;
  onRefresh: () => void;
  disconnecting: boolean;
}) {
  const [showSettings, setShowSettings] = useState(false);
  const [welcomeMsg, setWelcomeMsg] = useState(bot.welcomeMessage || "");
  const [systemPrompt, setSystemPrompt] = useState(bot.systemPrompt || "");
  const [saving, setSaving] = useState(false);

  const updateSettingsMutation = trpc.telegram.updateSettings.useMutation({
    onSuccess: () => {
      toast.success("تم حفظ الإعدادات بنجاح");
      setSaving(false);
      onRefresh();
    },
    onError: (err: any) => {
      toast.error(err.message);
      setSaving(false);
    },
  });

  const toggleChatMutation = trpc.telegram.toggleChat.useMutation({
    onSuccess: () => {
      toast.success("تم تحديث حالة المحادثة");
      onRefresh();
    },
  });

  const webhookOk = bot.webhookStatus?.url && !bot.webhookStatus?.last_error_message;

  return (
    <div className="space-y-6">
      {/* Bot Status Card */}
      <div className="bg-gradient-to-br from-[#26A5E4]/10 via-card/50 to-card/30 border border-[#26A5E4]/30 rounded-2xl p-6">
        <div className="flex items-start justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-[#26A5E4]/20 flex items-center justify-center">
              <TelegramIcon className="w-10 h-10" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-foreground flex items-center gap-2">
                @{bot.botUsername}
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              </h2>
              <p className="text-muted-foreground">{bot.botName}</p>
              <div className="flex items-center gap-3 mt-2">
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                  bot.isActive
                    ? "bg-emerald-500/20 text-emerald-400"
                    : "bg-red-500/20 text-red-400"
                }`}>
                  {bot.isActive ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                  {bot.isActive ? "نشط" : "غير نشط"}
                </span>
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                  webhookOk
                    ? "bg-emerald-500/20 text-emerald-400"
                    : "bg-amber-500/20 text-amber-400"
                }`}>
                  <Globe className="w-3 h-3" />
                  Webhook {webhookOk ? "متصل" : "يحتاج فحص"}
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={onRefresh} className="gap-1.5">
              <RefreshCw className="w-4 h-4" />
              تحديث
            </Button>
            <a
              href={`https://t.me/${bot.botUsername}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-2 text-sm bg-[#26A5E4]/20 hover:bg-[#26A5E4]/30 text-[#26A5E4] rounded-lg transition-colors"
            >
              <Send className="w-4 h-4" />
              فتح في Telegram
            </a>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-background/50 rounded-xl p-4 text-center">
            <Users className="w-5 h-5 text-[#26A5E4] mx-auto mb-2" />
            <div className="text-2xl font-bold text-foreground">{bot.chatCount || 0}</div>
            <div className="text-xs text-muted-foreground">محادثات نشطة</div>
          </div>
          <div className="bg-background/50 rounded-xl p-4 text-center">
            <MessageSquare className="w-5 h-5 text-emerald-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-foreground">
              {bot.chats?.reduce((sum: number, c: any) => sum + (c.messageCount || 0), 0) || 0}
            </div>
            <div className="text-xs text-muted-foreground">إجمالي الرسائل</div>
          </div>
          <div className="bg-background/50 rounded-xl p-4 text-center">
            <Zap className="w-5 h-5 text-amber-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-foreground">
              {bot.tokenPreview || "***"}
            </div>
            <div className="text-xs text-muted-foreground">توكن البوت</div>
          </div>
        </div>
      </div>

      {/* Active Chats */}
      {bot.chats && bot.chats.length > 0 && (
        <div className="bg-card/50 border border-border/50 rounded-2xl p-6">
          <h3 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
            <Users className="w-5 h-5 text-[#26A5E4]" />
            المحادثات النشطة ({bot.chats.length})
          </h3>
          <div className="space-y-3">
            {bot.chats.map((chat: any) => (
              <div
                key={chat.id}
                className="flex items-center justify-between p-4 bg-background/50 rounded-xl border border-border/30"
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-[#26A5E4]/20 flex items-center justify-center">
                    <User className="w-5 h-5 text-[#26A5E4]" />
                  </div>
                  <div>
                    <div className="font-medium text-foreground">
                      {chat.userName || "مستخدم"}
                      {chat.handle && (
                        <span className="text-muted-foreground text-sm mr-2">@{chat.handle}</span>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground flex items-center gap-2">
                      <span>{chat.chatType}</span>
                      <span>•</span>
                      <span>{chat.messageCount} رسالة</span>
                      {chat.lastMessageAt && (
                        <>
                          <span>•</span>
                          <span>آخر نشاط: {new Date(chat.lastMessageAt).toLocaleDateString("ar")}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <Button
                  variant={chat.isAllowed ? "outline" : "destructive"}
                  size="sm"
                  onClick={() =>
                    toggleChatMutation.mutate({
                      chatId: chat.id,
                      allowed: !chat.isAllowed,
                    })
                  }
                  className="gap-1.5"
                >
                  {chat.isAllowed ? (
                    <>
                      <Shield className="w-4 h-4" />
                      مفعّل
                    </>
                  ) : (
                    <>
                      <PowerOff className="w-4 h-4" />
                      محظور
                    </>
                  )}
                </Button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Settings */}
      <div className="bg-card/50 border border-border/50 rounded-2xl overflow-hidden">
        <button
          className="w-full flex items-center justify-between p-6 hover:bg-muted/30 transition-colors"
          onClick={() => setShowSettings(!showSettings)}
        >
          <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <Settings className="w-5 h-5 text-[#26A5E4]" />
            إعدادات البوت
          </h3>
          {showSettings ? (
            <ChevronUp className="w-5 h-5 text-muted-foreground" />
          ) : (
            <ChevronDown className="w-5 h-5 text-muted-foreground" />
          )}
        </button>

        {showSettings && (
          <div className="px-6 pb-6 space-y-5 border-t border-border/30 pt-5">
            <div>
              <label className="block text-sm font-medium text-foreground mb-2">
                رسالة الترحيب
              </label>
              <p className="text-xs text-muted-foreground mb-2">
                الرسالة التي تظهر عند إرسال /start
              </p>
              <textarea
                value={welcomeMsg}
                onChange={(e) => setWelcomeMsg(e.target.value)}
                rows={4}
                className="w-full bg-background/80 border border-border/50 rounded-xl p-3 text-foreground text-sm resize-none focus:ring-2 focus:ring-[#26A5E4]/50 focus:border-[#26A5E4]/50 outline-none"
                placeholder="مرحباً! أنا مساعدك الذكي..."
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-2">
                System Prompt (اختياري)
              </label>
              <p className="text-xs text-muted-foreground mb-2">
                تعليمات مخصصة للوكيل الذكي عند الرد على رسائل Telegram
              </p>
              <textarea
                value={systemPrompt}
                onChange={(e) => setSystemPrompt(e.target.value)}
                rows={4}
                dir="ltr"
                className="w-full bg-background/80 border border-border/50 rounded-xl p-3 text-foreground text-sm resize-none focus:ring-2 focus:ring-[#26A5E4]/50 focus:border-[#26A5E4]/50 outline-none font-mono"
                placeholder="You are a helpful AI assistant..."
              />
            </div>

            <div className="flex items-center gap-3">
              <Button
                onClick={() => {
                  setSaving(true);
                  updateSettingsMutation.mutate({
                    welcomeMessage: welcomeMsg,
                    systemPrompt: systemPrompt || undefined,
                  });
                }}
                disabled={saving}
                className="bg-[#26A5E4] hover:bg-[#26A5E4]/80 text-white gap-2"
              >
                {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                حفظ الإعدادات
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Danger Zone */}
      <div className="bg-red-500/5 border border-red-500/20 rounded-2xl p-6">
        <h3 className="text-lg font-semibold text-red-400 mb-2 flex items-center gap-2">
          <AlertCircle className="w-5 h-5" />
          منطقة الخطر
        </h3>
        <p className="text-sm text-muted-foreground mb-4">
          فصل البوت سيوقف استقبال الرسائل من Telegram. يمكنك إعادة الربط في أي وقت.
        </p>
        <Button
          variant="destructive"
          onClick={onDisconnect}
          disabled={disconnecting}
          className="gap-2"
        >
          {disconnecting ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <PowerOff className="w-4 h-4" />
          )}
          فصل البوت
        </Button>
      </div>
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────
export default function TelegramSetup() {
  const { user, isAuthenticated, loading: authLoading } = useAuth();
  const { t } = useTranslation();
  const [botToken, setBotToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [showGuide, setShowGuide] = useState(true);
  const [connecting, setConnecting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);

  const utils = trpc.useUtils();

  const { data: botData, isLoading: botLoading, refetch: refetchBot } = trpc.telegram.getBot.useQuery(
    undefined,
    { enabled: isAuthenticated }
  );

  const connectMutation = trpc.telegram.connect.useMutation({
    onSuccess: (data: any) => {
      toast.success(`تم ربط البوت @${data.bot?.username} بنجاح! 🎉`);
      setBotToken("");
      setConnecting(false);
      refetchBot();
    },
    onError: (err: any) => {
      toast.error("فشل ربط البوت", { description: err.message });
      setConnecting(false);
    },
  });

  const disconnectMutation = trpc.telegram.disconnect.useMutation({
    onSuccess: () => {
      toast.success("تم فصل البوت بنجاح");
      setDisconnecting(false);
      refetchBot();
    },
    onError: (err: any) => {
      toast.error(err.message);
      setDisconnecting(false);
    },
  });

  const handleConnect = () => {
    if (!botToken.trim()) {
      toast.error("الرجاء إدخال توكن البوت");
      return;
    }
    setConnecting(true);
    connectMutation.mutate({
      botToken: botToken.trim(),
      origin: window.location.origin,
    });
  };

  const handleDisconnect = () => {
    if (!confirm("هل أنت متأكد من فصل البوت؟ سيتوقف عن استقبال الرسائل.")) return;
    setDisconnecting(true);
    disconnectMutation.mutate();
  };

  // Auth loading
  if (authLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-[#26A5E4]" />
      </div>
    );
  }

  // Not authenticated
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <div className="text-center max-w-md">
          <TelegramIcon className="w-16 h-16 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-foreground mb-2">ربط Telegram</h2>
          <p className="text-muted-foreground mb-6">
            سجّل دخولك لربط بوت Telegram الخاص بك بالمنصة
          </p>
          <a href={getLoginUrl()} className="inline-flex items-center gap-2 px-6 py-3 bg-[#26A5E4] text-white rounded-xl font-medium hover:bg-[#26A5E4]/80 transition-colors">
            تسجيل الدخول
          </a>
        </div>
      </div>
    );
  }

  const isConnected = botData && botData.isActive;

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-background/80 backdrop-blur-xl border-b border-border/50">
        <div className="max-w-5xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
              {HAYO_LOGO ? (
                <img src={HAYO_LOGO} alt="HAYO" className="w-8 h-8 rounded-lg" />
              ) : (
                <Bot className="w-8 h-8 text-[#26A5E4]" />
              )}
            </Link>
            <div className="h-6 w-px bg-border/50" />
            <nav className="flex items-center gap-1 text-sm">
              <Link href="/integrations" className="text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
                <ArrowLeft className="w-4 h-4" />
                التكاملات
              </Link>
              <span className="text-muted-foreground mx-1">/</span>
              <span className="text-foreground font-medium flex items-center gap-1.5">
                <TelegramIcon className="w-4 h-4" />
                Telegram
              </span>
            </nav>
          </div>
          <div className="flex items-center gap-3">
            <LanguageSwitcher />
            <Link href="/chat" className="text-sm text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1.5">
              <MessageSquare className="w-4 h-4" />
              الدردشة
            </Link>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-5xl mx-auto px-4 py-8">
        {/* Page Title */}
        <div className="mb-8">
          <div className="flex items-center gap-4 mb-4">
            <div className="w-14 h-14 rounded-2xl bg-[#26A5E4]/20 flex items-center justify-center">
              <TelegramIcon className="w-9 h-9" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-foreground">ربط بوت Telegram</h1>
              <p className="text-muted-foreground">
                اربط بوت Telegram الخاص بك وتحدث مع الوكيل الذكي مباشرة من Telegram
              </p>
            </div>
          </div>

          {/* Feature highlights */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-6">
            <div className="flex items-center gap-3 p-3 bg-card/50 rounded-xl border border-border/30">
              <Bot className="w-5 h-5 text-[#26A5E4] shrink-0" />
              <span className="text-sm text-muted-foreground">وكيل ذكي يرد على رسائلك</span>
            </div>
            <div className="flex items-center gap-3 p-3 bg-card/50 rounded-xl border border-border/30">
              <Terminal className="w-5 h-5 text-emerald-400 shrink-0" />
              <span className="text-sm text-muted-foreground">تنفيذ أكواد وتحليل ملفات</span>
            </div>
            <div className="flex items-center gap-3 p-3 bg-card/50 rounded-xl border border-border/30">
              <Globe className="w-5 h-5 text-amber-400 shrink-0" />
              <span className="text-sm text-muted-foreground">دعم متعدد اللغات</span>
            </div>
          </div>
        </div>

        {botLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-8 h-8 animate-spin text-[#26A5E4]" />
          </div>
        ) : isConnected ? (
          <BotDashboard
            bot={botData}
            onDisconnect={handleDisconnect}
            onRefresh={() => refetchBot()}
            disconnecting={disconnecting}
          />
        ) : (
          <>
            {/* Setup Guide */}
            {showGuide && <SetupGuide onClose={() => setShowGuide(false)} />}

            {/* Connect Form */}
            <div className="bg-card/50 border border-border/50 rounded-2xl p-6">
              <h3 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
                <Plug className="w-5 h-5 text-[#26A5E4]" />
                ربط البوت
              </h3>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-foreground mb-2">
                    توكن البوت (Bot Token)
                  </label>
                  <div className="relative" dir="ltr">
                    <input
                      type={showToken ? "text" : "password"}
                      value={botToken}
                      onChange={(e) => setBotToken(e.target.value)}
                      placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
                      className="w-full bg-background/80 border border-border/50 rounded-xl px-4 py-3 text-foreground font-mono text-sm focus:ring-2 focus:ring-[#26A5E4]/50 focus:border-[#26A5E4]/50 outline-none pl-4 pr-12"
                    />
                    <button
                      type="button"
                      onClick={() => setShowToken(!showToken)}
                      className="absolute left-auto right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      {showToken ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                  <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
                    <Shield className="w-3 h-3" />
                    التوكن مشفر ولا يتم مشاركته مع أي طرف ثالث
                  </p>
                </div>

                <div className="flex items-center gap-3">
                  <Button
                    onClick={handleConnect}
                    disabled={connecting || !botToken.trim()}
                    className="bg-[#26A5E4] hover:bg-[#26A5E4]/80 text-white gap-2 px-6"
                  >
                    {connecting ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Plug className="w-4 h-4" />
                    )}
                    ربط البوت
                  </Button>

                  {!showGuide && (
                    <Button
                      variant="ghost"
                      onClick={() => setShowGuide(true)}
                      className="gap-1.5 text-muted-foreground"
                    >
                      <HelpCircle className="w-4 h-4" />
                      كيف أنشئ بوت؟
                    </Button>
                  )}
                </div>
              </div>
            </div>

            {/* How it works */}
            <div className="mt-8 bg-card/30 border border-border/30 rounded-2xl p-6">
              <h3 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
                <Info className="w-5 h-5 text-[#26A5E4]" />
                كيف يعمل؟
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="text-center">
                  <div className="w-12 h-12 rounded-2xl bg-[#26A5E4]/20 flex items-center justify-center mx-auto mb-3">
                    <Plug className="w-6 h-6 text-[#26A5E4]" />
                  </div>
                  <h4 className="font-medium text-foreground mb-1">1. ربط البوت</h4>
                  <p className="text-sm text-muted-foreground">
                    أنشئ بوت من BotFather والصق التوكن هنا
                  </p>
                </div>
                <div className="text-center">
                  <div className="w-12 h-12 rounded-2xl bg-emerald-500/20 flex items-center justify-center mx-auto mb-3">
                    <Send className="w-6 h-6 text-emerald-400" />
                  </div>
                  <h4 className="font-medium text-foreground mb-1">2. أرسل رسالة</h4>
                  <p className="text-sm text-muted-foreground">
                    أرسل أي رسالة للبوت في Telegram
                  </p>
                </div>
                <div className="text-center">
                  <div className="w-12 h-12 rounded-2xl bg-amber-500/20 flex items-center justify-center mx-auto mb-3">
                    <Bot className="w-6 h-6 text-amber-400" />
                  </div>
                  <h4 className="font-medium text-foreground mb-1">3. الوكيل يرد</h4>
                  <p className="text-sm text-muted-foreground">
                    الوكيل الذكي يعالج رسالتك ويرد عليك فوراً
                  </p>
                </div>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
