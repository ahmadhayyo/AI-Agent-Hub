/**
 * HAYO AI — Main Dashboard
 * Organized navigation hub for all 22+ platform features
 */
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  MessageSquare, Zap, User, ArrowRight, Loader2, Bot, Brain, Cpu,
  Shield, Upload, BarChart3, Clock, Sparkles, ChevronRight,
  LogOut, Home, Plus, Terminal, Code2, Swords, FileCode,
  Building2, TrendingUp, Lightbulb, Wand2, Link as LinkIcon,
  Rocket, Crown, Settings, Activity, CreditCard, BookOpen,
} from "lucide-react";
import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";

const HAYO_LOGO = `${import.meta.env.BASE_URL ?? "/"}logo.png`;

// ─── Page definitions organized by category ─────────────────────

export default function Dashboard() {
  const { user, loading: authLoading, isAuthenticated, logout } = useAuth();
  const { t } = useTranslation();
  const convListQuery = trpc.conversations.list.useQuery(undefined, { enabled: isAuthenticated });
  const { data: creditsData } = trpc.usage.credits.useQuery(undefined, { enabled: isAuthenticated });

  if (authLoading) return <div className="min-h-screen bg-background flex items-center justify-center"><Loader2 className="size-8 animate-spin text-primary" /></div>;

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center space-y-6 max-w-md px-4">
          <img src={HAYO_LOGO} alt="HAYO AI" className="w-20 h-20 rounded-2xl mx-auto shadow-lg shadow-indigo-500/25" />
          <h1 className="text-3xl font-bold">HAYO AI AGENT</h1>
          <p className="text-muted-foreground">منصة الذكاء الاصطناعي الشاملة — 22+ أداة احترافية</p>
          <a href={getLoginUrl()}>
            <Button size="lg" className="bg-gradient-to-r from-indigo-500 to-violet-600 text-white gap-2">
              تسجيل الدخول <ArrowRight className="size-4 rtl:rotate-180" />
            </Button>
          </a>
        </div>
      </div>
    );
  }

  const conversations = convListQuery.data || [];
  const isAdmin = user?.role === "admin";

  const SECTIONS = [
    {
      id: "ai", title: t("dashboard.sectionAI"), emoji: "🤖",
      gradient: "from-indigo-500/10 to-violet-500/10", border: "border-indigo-500/15",
      pages: [
        { href: "/chat", icon: MessageSquare, name: t("dashboard.smartChat"), desc: t("dashboard.smartChatDesc"), color: "from-indigo-500 to-violet-600", badge: t("common.essential") || "أساسي" },
        { href: "/agent", icon: Terminal, name: t("dashboard.codeAgent"), desc: t("dashboard.codeAgentDesc"), color: "from-emerald-500 to-teal-500", badge: t("common.advanced") || "متقدم" },
        { href: "/war-room", icon: Swords, name: t("dashboard.warRoom"), desc: t("dashboard.warRoomDesc"), color: "from-red-500 to-orange-500" },
        { href: "/prompt-factory", icon: Wand2, name: t("dashboard.promptFactory"), desc: t("dashboard.promptFactoryDesc"), color: "from-violet-500 to-purple-600" },
        { href: "/mindmap", icon: Brain, name: t("dashboard.mindMap") || "خريطة العقل", desc: t("dashboard.mindMapDesc") || "حوّل أي فكرة لخريطة ذهنية تفاعلية", color: "from-cyan-500 to-blue-500", badge: "🎁" },
      ],
    },
    {
      id: "dev", title: t("dashboard.sectionDev"), emoji: "⚙️",
      gradient: "from-emerald-500/10 to-cyan-500/10", border: "border-emerald-500/15",
      pages: [
        { href: "/byoc", icon: Code2, name: t("dashboard.ide"), desc: t("dashboard.ideDesc"), color: "from-cyan-500 to-blue-500" },
        { href: "/app-builder", icon: Rocket, name: t("dashboard.appBuilder"), desc: t("dashboard.appBuilderDesc"), color: "from-pink-500 to-rose-500" },
        { href: "/reverse", icon: FileCode, name: t("dashboard.reverseEng"), desc: t("dashboard.reverseEngDesc"), color: "from-amber-500 to-orange-500" },
        { href: "/integrations", icon: LinkIcon, name: t("dashboard.integrationsPage"), desc: t("dashboard.integrationsDesc"), color: "from-blue-500 to-indigo-500" },
        { href: "/osint", icon: Shield, name: t("dashboard.osint") || "أدوات OSINT", desc: t("dashboard.osintDesc") || "استخبارات مصادر مفتوحة — 9 أدوات حقيقية", color: "from-red-500 to-orange-500" },
      ],
    },
    {
      id: "office", title: t("dashboard.sectionOffice"), emoji: "📄",
      gradient: "from-blue-500/10 to-cyan-500/10", border: "border-blue-500/15",
      pages: [
        { href: "/office", icon: Building2, name: t("dashboard.officeSuite"), desc: t("dashboard.officeSuiteDesc"), color: "from-blue-600 to-cyan-500" },
        { href: "/studies", icon: Lightbulb, name: t("dashboard.studies"), desc: t("dashboard.studiesDesc"), color: "from-amber-500 to-orange-500" },
        { href: "/islam", icon: BookOpen, name: "رسالة الإسلام", desc: "القرآن الكريم • الحديث النبوي • المذاهب الأربعة • الإعجاز العلمي", color: "from-emerald-600 to-teal-600" },
      ],
    },
    {
      id: "trading", title: t("dashboard.sectionTrading"), emoji: "📈",
      gradient: "from-emerald-500/10 to-green-500/10", border: "border-emerald-500/15",
      pages: [
        { href: "/trading", icon: TrendingUp, name: t("dashboard.tradingAnalysis"), desc: t("dashboard.tradingDesc"), color: "from-emerald-500 to-green-600" },
        { href: "/ea-factory", icon: Cpu, name: t("dashboard.eaFactory"), desc: t("dashboard.eaFactoryDesc"), color: "from-violet-500 to-fuchsia-500" },
      ],
    },
    {
      id: "admin", title: t("dashboard.sectionAdmin"), emoji: "🔒",
      gradient: "from-red-500/10 to-pink-500/10", border: "border-red-500/15",
      adminOnly: true,
      pages: [
        { href: "/admin", icon: Crown, name: t("dashboard.adminPanel"), desc: t("dashboard.adminDesc"), color: "from-amber-500 to-yellow-500" },
        { href: "/maintenance", icon: Activity, name: t("dashboard.maintenance"), desc: t("dashboard.maintenanceDesc"), color: "from-red-500 to-pink-500" },
        { href: "/telegram", icon: Bot, name: t("dashboard.telegramBot"), desc: t("dashboard.telegramDesc"), color: "from-blue-400 to-cyan-400" },
      ],
    },
  ];

  return (
    <div className="min-h-screen bg-background" dir="rtl">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto flex items-center justify-between h-14 px-4">
          <Link href="/" className="flex items-center gap-2">
            <img src={HAYO_LOGO} alt="HAYO AI" className="w-8 h-8 rounded-lg" />
            <span className="font-bold text-sm">HAYO AI</span>
          </Link>
          <div className="flex items-center gap-2">
            <Link href="/chat"><Button variant="ghost" size="sm" className="text-xs gap-1"><MessageSquare className="size-3.5" /> الدردشة</Button></Link>
            <Link href="/pricing"><Button variant="ghost" size="sm" className="text-xs gap-1"><CreditCard className="size-3.5" /> الأسعار</Button></Link>
            <Link href="/account"><Button variant="ghost" size="sm" className="text-xs gap-1"><User className="size-3.5" /> {t("nav.account") || "حسابي"}</Button></Link>
            <LanguageSwitcher />
            <Button variant="ghost" size="sm" className="text-xs gap-1 text-destructive" onClick={() => logout()}><LogOut className="size-3.5" /></Button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
        {/* Welcome + Stats */}
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-2xl font-bold">{t("dashboard.welcome") + "،"} {user?.name || "مستخدم"} 👋</h1>
            <p className="text-muted-foreground text-sm mt-1">{t("dashboard.subtitle")}</p>
          </div>
          <div className="flex items-center gap-3">
            {creditsData && (
              <div className="bg-card border border-border rounded-xl px-4 py-2 text-center">
                <p className="text-[10px] text-muted-foreground">{t("dashboard.todayCredits")}</p>
                <p className="text-lg font-bold text-primary">{creditsData.isUnlimited ? "∞" : creditsData.remaining} <span className="text-xs text-muted-foreground font-normal">💎</span></p>
              </div>
            )}
            <Link href="/chat">
              <Button className="bg-gradient-to-r from-indigo-500 to-violet-600 text-white gap-2 h-11">
                <Plus className="size-4" /> محادثة جديدة
              </Button>
            </Link>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center"><MessageSquare className="size-5 text-white" /></div>
            <div><p className="text-xs text-muted-foreground">{t("dashboard.conversations")}</p><p className="text-xl font-bold">{conversations.length}</p></div>
          </div>
          <div className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center"><Bot className="size-5 text-white" /></div>
            <div><p className="text-xs text-muted-foreground">{t("dashboard.aiModels")}</p><p className="text-xl font-bold">6+</p></div>
          </div>
          <div className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500 to-orange-500 flex items-center justify-center"><Zap className="size-5 text-white" /></div>
            <div><p className="text-xs text-muted-foreground">{t("dashboard.tools")}</p><p className="text-xl font-bold">22+</p></div>
          </div>
          <div className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-500 flex items-center justify-center"><LinkIcon className="size-5 text-white" /></div>
            <div><p className="text-xs text-muted-foreground">{t("dashboard.integrations")}</p><p className="text-xl font-bold">35+</p></div>
          </div>
        </div>

        {/* Sections */}
        {SECTIONS.map(section => {
          if (section.adminOnly && !isAdmin) return null;
          return (
            <div key={section.id} className="space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-lg">{section.emoji}</span>
                <h2 className="text-lg font-bold">{section.title}</h2>
                <div className="flex-1 h-px bg-border mr-2" />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {(section.pages as Array<{ href: string; icon: any; name: string; desc: string; color: string; badge?: string }>).map(page => (
                  <Link key={page.href} href={page.href}>
                    <div className="group bg-card border border-border rounded-2xl p-5 hover:border-primary/30 hover:shadow-lg hover:shadow-primary/5 transition-all cursor-pointer h-full flex flex-col">
                      <div className="flex items-center gap-3 mb-3">
                        <div className={cn("w-10 h-10 rounded-xl bg-gradient-to-br flex items-center justify-center shrink-0", page.color)}>
                          <page.icon className="size-5 text-white" />
                        </div>
                        {page.badge && (
                          <span className="text-[9px] px-2 py-0.5 rounded-full bg-primary/10 text-primary font-medium">{page.badge}</span>
                        )}
                        <ChevronRight className="size-4 text-muted-foreground mr-auto opacity-0 group-hover:opacity-100 transition-opacity rtl:rotate-180" />
                      </div>
                      <h3 className="font-bold text-sm">{page.name}</h3>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed flex-1">{page.desc}</p>
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          );
        })}

        {/* Recent Conversations */}
        {conversations.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-lg">💬</span>
                <h2 className="text-lg font-bold">{t("dashboard.recentChats")}</h2>
              </div>
              <Link href="/chat"><Button variant="ghost" size="sm" className="text-xs">{t("dashboard.viewAll")} <ChevronRight className="size-3.5 mr-1 rtl:rotate-180" /></Button></Link>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {conversations.slice(0, 6).map((conv: any) => (
                <Link key={conv.id} href="/chat">
                  <div className="bg-card border border-border rounded-xl p-4 hover:border-primary/30 transition-colors cursor-pointer flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                      <MessageSquare className="size-4 text-primary" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{conv.title}</p>
                      <p className="text-[10px] text-muted-foreground flex items-center gap-1 mt-0.5">
                        <Clock className="size-3" />
                        {new Date(conv.updatedAt).toLocaleDateString("ar-SA")}
                      </p>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* System Status */}
        <div className="bg-card border border-border rounded-2xl p-5">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center">
              <Bot className="size-6 text-white" />
            </div>
            <div className="flex-1">
              <h3 className="font-bold">HAYO AI AGENT Platform</h3>
              <p className="text-sm text-muted-foreground mt-0.5">
                6 نماذج AI • 22+ أداة • 35+ تكامل • 7 أقسام دراسات • EA Factory • تداول آلي
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-sm text-emerald-400 font-medium">{t("dashboard.allSystemsOnline")}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
