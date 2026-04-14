import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { getLoginUrl } from "@/const";
import { Link } from "wouter";
import { useState } from "react";
import {
  User, Key, Crown, Shield, Copy, Plus, Trash2, RefreshCw,
  ArrowLeft, Zap, BarChart3, Calendar, Clock, Check, Eye, EyeOff
} from "lucide-react";
import { toast } from "sonner";

export default function MyAccount() {
  const { user, isAuthenticated, loading, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<"overview" | "keys" | "usage">("overview");

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center">
        <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center text-white">
        <div className="text-center">
          <Shield className="w-16 h-16 text-indigo-400 mx-auto mb-4" />
          <h1 className="text-2xl font-bold mb-2">تسجيل الدخول مطلوب</h1>
          <p className="text-gray-400 mb-6">يجب تسجيل الدخول لعرض حسابك</p>
          <a href={getLoginUrl()}><Button className="bg-gradient-to-r from-indigo-500 to-purple-600">تسجيل الدخول</Button></a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white">
      {/* Header */}
      <header className="border-b border-white/5 bg-[#0a0a0f]/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-5xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/" className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors">
              <ArrowLeft className="w-4 h-4" />
              <span className="text-sm">الرئيسية</span>
            </Link>
            <div className="h-6 w-px bg-white/10" />
            <span className="font-bold">حسابي</span>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/chat"><Button variant="ghost" size="sm">الدردشة</Button></Link>
            {user?.role === "admin" && (
              <Link href="/admin"><Button variant="ghost" size="sm" className="text-amber-400">لوحة المدير</Button></Link>
            )}
            <Button variant="ghost" size="sm" onClick={() => logout()}>تسجيل الخروج</Button>
          </div>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-6 py-8">
        {/* Profile Card */}
        <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-6 mb-8">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-2xl font-bold">
              {(user?.name || "U")[0].toUpperCase()}
            </div>
            <div>
              <h1 className="text-xl font-bold">{user?.name || "مستخدم"}</h1>
              <p className="text-sm text-gray-400">{user?.email || ""}</p>
              <div className="flex items-center gap-2 mt-1">
                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${
                  user?.role === "admin" ? "bg-amber-500/20 text-amber-300" : "bg-indigo-500/20 text-indigo-300"
                }`}>
                  {user?.role === "admin" ? <Crown className="w-3 h-3" /> : <User className="w-3 h-3" />}
                  {user?.role === "admin" ? "مدير" : "مستخدم"}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-8 border-b border-white/5 pb-4">
          {[
            { id: "overview" as const, label: "نظرة عامة", icon: BarChart3 },
            { id: "keys" as const, label: "مفاتيح API", icon: Key },
            { id: "usage" as const, label: "الاستخدام", icon: Clock },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab.id
                  ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30"
                  : "text-gray-400 hover:text-white hover:bg-white/5"
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === "overview" && <OverviewTab />}
        {activeTab === "keys" && <KeysTab />}
        {activeTab === "usage" && <UsageTab />}
      </div>
    </div>
  );
}

function OverviewTab() {
  const { data: sub, isLoading } = trpc.usage.subscription.useQuery();

  if (isLoading) {
    return <div className="space-y-4">{[1, 2].map(i => <div key={i} className="h-32 rounded-xl bg-white/5 animate-pulse" />)}</div>;
  }

  return (
    <div className="space-y-6">
      {/* Current Plan */}
      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6">
        <h3 className="font-semibold mb-4 flex items-center gap-2">
          <Crown className="w-5 h-5 text-amber-400" />
          خطتك الحالية
        </h3>
        {sub?.plan ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-lg font-bold">{sub.plan.displayName}</p>
                <p className="text-sm text-gray-400">{sub.plan.description}</p>
              </div>
              <div className="text-left">
                {sub.plan.name === "owner" ? (
                  <span className="text-xl font-bold text-amber-400">غير محدود</span>
                ) : (
                  <p className="text-2xl font-bold">${sub.plan.priceMonthly}<span className="text-sm text-gray-400">/شهر</span></p>
                )}
              </div>
            </div>
            {sub.subscription && (
              <div className="flex items-center gap-4 text-sm text-gray-400">
                <span className="flex items-center gap-1">
                  <Calendar className="w-4 h-4" />
                  ينتهي: {new Date(sub.subscription.endDate).toLocaleDateString("ar")}
                </span>
                <span className={`px-2 py-0.5 rounded text-xs ${
                  sub.subscription.status === "active" ? "bg-emerald-500/20 text-emerald-300" : "bg-red-500/20 text-red-300"
                }`}>
                  {sub.subscription.status === "active" ? "نشط" : sub.subscription.status}
                </span>
              </div>
            )}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
              <MiniStat label="رسائل/يوم" value={sub.plan.dailyMessageLimit >= 999999 ? "∞" : sub.plan.dailyMessageLimit === -1 ? "∞" : String(sub.plan.dailyMessageLimit)} />
              <MiniStat label="رفع ملفات" value={`${sub.plan.maxFileUploadMB}MB`} />
              <MiniStat label="تنفيذ كود" value={`${sub.plan.maxCodeExecutionSec}ث`} />
              <MiniStat label="بحث ويب" value={sub.plan.canUseWebSearch ? "✓" : "✗"} />
            </div>
          </div>
        ) : (
          <div className="text-center py-8">
            <Zap className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400 mb-4">أنت على الخطة المجانية</p>
            <Link href="/pricing"><Button className="bg-gradient-to-r from-indigo-500 to-purple-600">ترقية الخطة</Button></Link>
          </div>
        )}
      </div>
    </div>
  );
}

function KeysTab() {
  const { data: keys, isLoading, refetch } = trpc.apiKeys.list.useQuery();
  const createKey = trpc.apiKeys.create.useMutation({
    onSuccess: (data: any) => {
      setNewKey(data.rawKey);
      toast.success("تم إنشاء المفتاح بنجاح");
      refetch();
    },
    onError: (e: any) => toast.error(e.message),
  });
  const revokeKey = trpc.apiKeys.revoke.useMutation({
    onSuccess: () => { toast.success("تم إلغاء المفتاح"); refetch(); },
    onError: (e: any) => toast.error(e.message),
  });
  const { data: plans } = trpc.plans.list.useQuery();

  const [newKey, setNewKey] = useState<string | null>(null);
  const [keyLabel, setKeyLabel] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [showKey, setShowKey] = useState<Record<number, boolean>>({});

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h3 className="font-semibold">مفاتيح API الخاصة بك</h3>
        <Button
          size="sm"
          onClick={() => setShowCreate(!showCreate)}
          className="bg-gradient-to-r from-indigo-500 to-purple-600"
        >
          <Plus className="w-4 h-4 ml-1" />
          مفتاح جديد
        </Button>
      </div>

      {/* New key creation */}
      {showCreate && (
        <div className="rounded-xl border border-indigo-500/30 bg-indigo-500/5 p-4 mb-6">
          <div className="flex gap-3">
            <input
              value={keyLabel}
              onChange={e => setKeyLabel(e.target.value)}
              placeholder="اسم المفتاح (مثال: تطبيق الجوال)"
              className="flex-1 bg-white/5 border border-white/10 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-indigo-500/50"
            />
            <Button
              onClick={() => {
                if (!keyLabel.trim()) { toast.error("أدخل اسم المفتاح"); return; }
                // Get free plan for self-service key creation
const freePlan = plans?.find((p: any) => p.name === 'free');
createKey.mutate({ label: keyLabel.trim(), planId: freePlan?.id || 1, durationDays: 30 });
                setKeyLabel("");
                setShowCreate(false);
              }}
              disabled={createKey.isPending}
              size="sm"
            >
              {createKey.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : "إنشاء"}
            </Button>
          </div>
        </div>
      )}

      {/* New key display */}
      {newKey && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 mb-6">
          <div className="flex items-center gap-2 mb-2">
            <Check className="w-4 h-4 text-emerald-400" />
            <span className="text-sm font-medium text-emerald-300">تم إنشاء المفتاح - انسخه الآن! لن يظهر مرة أخرى</span>
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-black/30 rounded px-3 py-2 text-sm font-mono text-emerald-300 break-all">{newKey}</code>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => { navigator.clipboard.writeText(newKey); toast.success("تم النسخ"); }}
            >
              <Copy className="w-4 h-4" />
            </Button>
          </div>
          <Button variant="ghost" size="sm" className="mt-2 text-gray-400" onClick={() => setNewKey(null)}>إخفاء</Button>
        </div>
      )}

      {/* Keys list */}
      {isLoading ? (
        <div className="space-y-3">{[1, 2].map(i => <div key={i} className="h-16 rounded-xl bg-white/5 animate-pulse" />)}</div>
      ) : (
        <div className="space-y-3">
          {(keys || []).map((k: any) => (
            <div key={k.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Key className={`w-5 h-5 ${k.isActive ? "text-indigo-400" : "text-gray-600"}`} />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{k.label}</span>
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      k.isActive ? "bg-emerald-500/20 text-emerald-300" : "bg-red-500/20 text-red-300"
                    }`}>
                      {k.isActive ? "نشط" : "ملغى"}
                    </span>
                  </div>
                  <code className="text-xs text-gray-500 font-mono mt-1 block">
                    {k.keyHash?.slice(0, 16)}...
                  </code>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {k.isActive && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => revokeKey.mutate({ id: k.id })}
                    className="text-red-400 hover:text-red-300"
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                )}
              </div>
            </div>
          ))}
          {(keys || []).length === 0 && (
            <div className="text-center py-12 text-gray-500">
              <Key className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>لم تنشئ أي مفتاح API بعد</p>
              <p className="text-xs mt-1">أنشئ مفتاحاً للوصول إلى HAYO AI من تطبيقاتك</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function UsageTab() {
  const { data: usage, isLoading } = trpc.usage.daily.useQuery();
  const { data: sub } = trpc.usage.subscription.useQuery();

  if (isLoading) {
    return <div className="h-48 rounded-xl bg-white/5 animate-pulse" />;
  }

  const plan = sub?.plan;
  const dailyLimit = plan?.dailyMessageLimit || 10;
  const messagesUsed = usage?.messagesCount || 0;
  const codeUsed = usage?.codeExecutions || 0;
  const filesUsed = usage?.fileCreations || 0;
  const searchUsed = usage?.webSearches || 0;

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6">
        <h3 className="font-semibold mb-6">استخدامك اليوم</h3>
        <div className="space-y-5">
          <UsageBar label="الرسائل" used={messagesUsed} limit={dailyLimit === -1 ? 999 : dailyLimit} color="indigo" />
          <UsageBar label="تنفيذ الكود" used={codeUsed} limit={50} color="emerald" />
          <UsageBar label="رفع الملفات" used={filesUsed} limit={20} color="amber" />
          <UsageBar label="بحث الويب" used={searchUsed} limit={plan?.canUseWebSearch ? 30 : 0} color="purple" />
        </div>
      </div>
    </div>
  );
}

function UsageBar({ label, used, limit, color }: { label: string; used: number; limit: number; color: string }) {
  const pct = limit > 0 ? Math.min(100, (used / limit) * 100) : 0;
  const colors: Record<string, string> = {
    indigo: "from-indigo-500 to-indigo-600",
    emerald: "from-emerald-500 to-emerald-600",
    amber: "from-amber-500 to-amber-600",
    purple: "from-purple-500 to-purple-600",
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm text-gray-300">{label}</span>
        <span className="text-sm text-gray-400">{used} / {limit === 999 ? "∞" : limit}</span>
      </div>
      <div className="h-2 bg-white/5 rounded-full overflow-hidden">
        <div
          className={`h-full bg-gradient-to-r ${colors[color]} rounded-full transition-all duration-500`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg bg-white/5 p-3 text-center">
      <p className="text-lg font-bold">{value}</p>
      <p className="text-xs text-gray-400">{label}</p>
    </div>
  );
}
