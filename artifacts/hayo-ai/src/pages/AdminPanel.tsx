import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { useState } from "react";
import {
  Users, Key, BarChart3, Shield,
  Copy, Trash2, RefreshCw, Search,
  ArrowLeft, Crown, AlertTriangle, CreditCard,
  KeyRound, CheckCircle, XCircle, Plus,
} from "lucide-react";
import { toast } from "sonner";

export default function AdminPanel() {
  const { user, isAuthenticated, loading } = useAuth();
  const [, navigate] = useLocation();
  const [activeTab, setActiveTab] = useState<"users" | "keys" | "stats" | "subscribers" | "codes">("users");

  // Admin check
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
          <Shield className="w-16 h-16 text-red-400 mx-auto mb-4" />
          <h1 className="text-2xl font-bold mb-2">الوصول مرفوض</h1>
          <p className="text-gray-400 mb-6">يجب تسجيل الدخول للوصول للوحة التحكم</p>
          <Link href="/"><Button>العودة للرئيسية</Button></Link>
        </div>
      </div>
    );
  }

  if (user?.role !== "admin") {
    return (
      <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center text-white">
        <div className="text-center">
          <AlertTriangle className="w-16 h-16 text-amber-400 mx-auto mb-4" />
          <h1 className="text-2xl font-bold mb-2">صلاحيات غير كافية</h1>
          <p className="text-gray-400 mb-6">هذه الصفحة متاحة فقط للمديرين</p>
          <Link href="/"><Button>العودة للرئيسية</Button></Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white">
      {/* Header */}
      <header className="border-b border-white/5 bg-[#0a0a0f]/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/" className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors">
              <ArrowLeft className="w-4 h-4" />
              <span className="text-sm">الرئيسية</span>
            </Link>
            <div className="h-6 w-px bg-white/10" />
            <div className="flex items-center gap-2">
              <Crown className="w-5 h-5 text-amber-400" />
              <span className="font-bold">لوحة تحكم المدير</span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-sm text-gray-400">{user?.name || user?.email}</span>
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center text-xs font-bold">
              {(user?.name || "A")[0].toUpperCase()}
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Tabs */}
        <div className="flex gap-2 mb-8 border-b border-white/5 pb-4 flex-wrap">
          {[
            { id: "users" as const, label: "المستخدمون", icon: Users },
            { id: "codes" as const, label: "كودات الاشتراك", icon: KeyRound },
            { id: "subscribers" as const, label: "المشتركون", icon: CreditCard },
            { id: "keys" as const, label: "مفاتيح API", icon: Key },
            { id: "stats" as const, label: "الإحصائيات", icon: BarChart3 },
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

        {/* Content */}
        {activeTab === "users" && <UsersTab />}
        {activeTab === "codes" && <CodesTab />}
        {activeTab === "keys" && <KeysTab />}
        {activeTab === "stats" && <StatsTab />}
        {activeTab === "subscribers" && <SubscriberManagement />}
      </div>
    </div>
  );
}

function UsersTab() {
  const { data: users, isLoading } = trpc.admin.users.list.useQuery();
  const { data: plans } = trpc.plans.list.useQuery();
  const [search, setSearch] = useState("");

  const filteredUsers = (users || []).filter((u: any) =>
    (u.name || "").toLowerCase().includes(search.toLowerCase()) ||
    (u.email || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">المستخدمون ({users?.length || 0})</h2>
        <div className="relative">
          <Search className="w-4 h-4 absolute right-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="بحث..."
            className="bg-white/5 border border-white/10 rounded-lg pr-10 pl-4 py-2 text-sm focus:outline-none focus:border-indigo-500/50"
          />
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {[1, 2, 3].map(i => <div key={i} className="h-16 rounded-xl bg-white/5 animate-pulse" />)}
        </div>
      ) : (
        <div className="rounded-xl border border-white/10 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="bg-white/5 text-sm text-gray-400">
                <th className="text-right px-4 py-3 font-medium">المستخدم</th>
                <th className="text-right px-4 py-3 font-medium">البريد</th>
                <th className="text-right px-4 py-3 font-medium">الدور</th>
                <th className="text-right px-4 py-3 font-medium">التسجيل</th>
                <th className="text-right px-4 py-3 font-medium">ID</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((u: any) => (
                <tr key={u.id} className="border-t border-white/5 hover:bg-white/[0.02]">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-xs font-bold">
                        {(u.name || "U")[0].toUpperCase()}
                      </div>
                      <span className="text-sm font-medium">{u.name || "بدون اسم"}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-400">{u.email || "-"}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex px-2 py-1 rounded text-xs font-medium ${
                      u.role === "admin" ? "bg-amber-500/20 text-amber-300" : "bg-indigo-500/20 text-indigo-300"
                    }`}>
                      {u.role === "admin" ? "مدير" : "مستخدم"}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-400">
                    {new Date(u.createdAt).toLocaleDateString("ar")}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500 font-mono text-xs">{u.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function CodesTab() {
  const { data: codes, isLoading, refetch } = trpc.codes.list.useQuery();
  const { data: plans } = trpc.plans.list.useQuery();

  const [planId, setPlanId] = useState("");
  const [count, setCount] = useState(1);
  const [duration, setDuration] = useState(30);
  const [note, setNote] = useState("");
  const [generatedCodes, setGeneratedCodes] = useState<string[]>([]);
  const [search, setSearch] = useState("");

  const generateMutation = trpc.codes.generate.useMutation({
    onSuccess: (data: any) => {
      setGeneratedCodes(data.codes);
      toast.success(`✅ تم توليد ${data.codes.length} كود`);
      refetch();
    },
    onError: (e: any) => toast.error(e.message),
  });

  const deactivateMutation = trpc.codes.deactivate.useMutation({
    onSuccess: () => { toast.success("تم إلغاء الكود"); refetch(); },
    onError: (e: any) => toast.error(e.message),
  });

  const copyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    toast.success("تم نسخ الكود");
  };

  const copyAll = () => {
    navigator.clipboard.writeText(generatedCodes.join("\n"));
    toast.success(`تم نسخ ${generatedCodes.length} كود`);
  };

  const filteredCodes = (codes || []).filter((c: any) =>
    !search || c.code?.toLowerCase().includes(search.toLowerCase()) ||
    c.usedByEmail?.toLowerCase().includes(search.toLowerCase()) ||
    c.note?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <KeyRound className="w-5 h-5 text-emerald-400" />
        كودات الاشتراك
      </h2>

      {/* Generate Codes */}
      <div className="p-5 rounded-xl border border-emerald-500/20 bg-emerald-500/5 space-y-4">
        <h3 className="font-semibold text-emerald-400 flex items-center gap-2">
          <Plus className="w-4 h-4" />
          توليد كودات جديدة
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <select
            value={planId}
            onChange={e => setPlanId(e.target.value)}
            className="px-3 py-2 rounded-lg border border-white/10 bg-black/40 text-sm focus:outline-none focus:border-emerald-500/50 col-span-2 md:col-span-1"
          >
            <option value="">اختر الخطة...</option>
            {(plans || []).map((p: any) => (
              <option key={p.id} value={p.id}>{p.displayName}</option>
            ))}
          </select>
          <div className="flex items-center gap-2">
            <label className="text-xs text-gray-400 whitespace-nowrap">عدد الأيام:</label>
            <input
              type="number"
              value={duration}
              onChange={e => setDuration(Number(e.target.value))}
              min={1} max={365}
              className="flex-1 px-3 py-2 rounded-lg border border-white/10 bg-black/40 text-sm focus:outline-none focus:border-emerald-500/50"
            />
          </div>
          <div className="flex items-center gap-2">
            <label className="text-xs text-gray-400 whitespace-nowrap">العدد:</label>
            <input
              type="number"
              value={count}
              onChange={e => setCount(Number(e.target.value))}
              min={1} max={50}
              className="flex-1 px-3 py-2 rounded-lg border border-white/10 bg-black/40 text-sm focus:outline-none focus:border-emerald-500/50"
            />
          </div>
          <input
            value={note}
            onChange={e => setNote(e.target.value)}
            placeholder="ملاحظة اختيارية..."
            className="px-3 py-2 rounded-lg border border-white/10 bg-black/40 text-sm focus:outline-none focus:border-emerald-500/50"
          />
        </div>
        <button
          onClick={() => {
            if (!planId) { toast.error("اختر الخطة أولاً"); return; }
            generateMutation.mutate({ planId: Number(planId), durationDays: duration, count, note: note || undefined });
          }}
          disabled={generateMutation.isPending || !planId}
          className="w-full py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700 text-white font-semibold text-sm transition-all disabled:opacity-50"
        >
          {generateMutation.isPending ? "⏳ جارٍ التوليد..." : `✨ توليد ${count} كود`}
        </button>

        {/* Generated codes result */}
        {generatedCodes.length > 0 && (
          <div className="bg-black/40 rounded-xl border border-emerald-500/30 p-4 space-y-2">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm font-medium text-emerald-400">الكودات المولّدة ({generatedCodes.length})</span>
              <button
                onClick={copyAll}
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30 transition-colors"
              >
                <Copy className="w-3 h-3" />
                نسخ الكل
              </button>
            </div>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {generatedCodes.map((code, i) => (
                <div key={i} className="flex items-center justify-between bg-black/60 rounded-lg px-3 py-2">
                  <code className="font-mono text-sm text-white tracking-widest">{code}</code>
                  <button onClick={() => copyCode(code)} className="text-gray-400 hover:text-white transition-colors">
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Codes List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-sm text-gray-300">
            جميع الكودات ({(codes || []).length})
          </h3>
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute right-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="بحث..."
              className="bg-white/5 border border-white/10 rounded-lg pr-9 pl-3 py-1.5 text-sm focus:outline-none focus:border-indigo-500/50 w-44"
            />
          </div>
        </div>

        {isLoading ? (
          <div className="space-y-2">
            {[1, 2, 3].map(i => <div key={i} className="h-16 rounded-xl bg-white/5 animate-pulse" />)}
          </div>
        ) : (
          <div className="rounded-xl border border-white/10 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-white/5 text-gray-400">
                  <th className="text-right px-4 py-3 font-medium">الكود</th>
                  <th className="text-right px-4 py-3 font-medium">الخطة</th>
                  <th className="text-right px-4 py-3 font-medium">المدة</th>
                  <th className="text-right px-4 py-3 font-medium">الحالة</th>
                  <th className="text-right px-4 py-3 font-medium">المستخدم</th>
                  <th className="text-right px-4 py-3 font-medium">تاريخ الانتهاء</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {filteredCodes.map((c: any) => (
                  <tr key={c.id} className="border-t border-white/5 hover:bg-white/[0.02]">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <code className="font-mono text-xs text-white tracking-wide">{c.code}</code>
                        <button onClick={() => copyCode(c.code)} className="text-gray-600 hover:text-gray-400 transition-colors">
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-400">{c.planName || "—"}</td>
                    <td className="px-4 py-3 text-gray-400">{c.durationDays} يوم</td>
                    <td className="px-4 py-3">
                      {c.usedAt ? (
                        <span className="flex items-center gap-1 text-xs text-gray-400">
                          <XCircle className="w-3 h-3 text-gray-500" />
                          مستخدم
                        </span>
                      ) : c.isActive ? (
                        <span className="flex items-center gap-1 text-xs text-emerald-400">
                          <CheckCircle className="w-3 h-3" />
                          متاح
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-xs text-red-400">
                          <XCircle className="w-3 h-3" />
                          ملغى
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">{c.usedByEmail || "—"}</td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {c.expiresAt ? new Date(c.expiresAt).toLocaleDateString("ar-SA") : "—"}
                    </td>
                    <td className="px-4 py-3">
                      {c.isActive && !c.usedAt && (
                        <button
                          onClick={() => {
                            if (confirm(`إلغاء الكود ${c.code}؟`)) deactivateMutation.mutate({ id: c.id });
                          }}
                          className="text-red-400 hover:text-red-300 transition-colors"
                          title="إلغاء"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {filteredCodes.length === 0 && (
                  <tr>
                    <td colSpan={7} className="text-center py-12 text-gray-500">
                      <KeyRound className="w-10 h-10 mx-auto mb-2 opacity-30" />
                      <p>لا توجد كودات بعد — ولّد كوداً جديداً أعلاه</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function KeysTab() {
  const { data: keys, isLoading, refetch } = trpc.admin.apiKeys.list.useQuery();
  const revokeKey = trpc.admin.apiKeys.revoke.useMutation({
    onSuccess: () => { toast.success("تم إلغاء المفتاح"); refetch(); },
    onError: (e: any) => toast.error(e.message),
  });

  const copyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    toast.success("تم نسخ المفتاح");
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">مفاتيح API ({keys?.length || 0})</h2>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {[1, 2, 3].map(i => <div key={i} className="h-16 rounded-xl bg-white/5 animate-pulse" />)}
        </div>
      ) : (
        <div className="space-y-3">
          {(keys || []).map((k: any) => (
            <div key={k.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                  k.isActive ? "bg-emerald-500/20" : "bg-red-500/20"
                }`}>
                  <Key className={`w-5 h-5 ${k.isActive ? "text-emerald-400" : "text-red-400"}`} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{k.name}</span>
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      k.isActive ? "bg-emerald-500/20 text-emerald-300" : "bg-red-500/20 text-red-300"
                    }`}>
                      {k.isActive ? "نشط" : "ملغى"}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 mt-1">
                    <code className="text-xs text-gray-500 font-mono">
                      {k.keyPreview || k.key?.slice(0, 12) + "..."}
                    </code>
                    <span className="text-xs text-gray-500">المالك: {k.userName || "غير معروف"}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {k.isActive && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => revokeKey.mutate({ id: k.id })}
                    className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
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
              <p>لا توجد مفاتيح API بعد</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatsTab() {
  const { data: stats, isLoading } = trpc.admin.stats.useQuery();

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">إحصائيات المنصة</h2>

      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => <div key={i} className="h-32 rounded-xl bg-white/5 animate-pulse" />)}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <StatCard label="إجمالي المستخدمين" value={stats?.totalUsers || 0} icon={Users} color="indigo" />
            <StatCard label="مفاتيح API النشطة" value={stats?.activeApiKeys || 0} icon={Key} color="emerald" />
            <StatCard label="الرسائل اليوم" value={stats?.todayMessages || 0} icon={BarChart3} color="amber" />
            <StatCard label="الاشتراكات النشطة" value={stats?.activeSubscriptions || 0} icon={Crown} color="purple" />
          </div>

          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6">
            <h3 className="font-semibold mb-4">توزيع الخطط</h3>
            <div className="space-y-3">
              {[
                  { label: "إجمالي المحادثات", value: stats?.totalConversations || 0 },
                  { label: "إجمالي الرسائل", value: stats?.totalMessages || 0 },
                  { label: "تنفيذ كود اليوم", value: stats?.todayCodeExecutions || 0 },
                ].map((item) => (
                <div key={item.label} className="flex items-center gap-4">
                  <span className="text-sm text-gray-400 w-32">{item.label}</span>
                  <div className="flex-1 h-6 bg-white/5 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-indigo-500 to-purple-600 rounded-full transition-all"
                      style={{ width: `${Math.min(100, (Number(item.value) / Math.max(Number(stats?.totalMessages || 1), 1)) * 100)}%` }}
                    />
                  </div>
                  <span className="text-sm font-medium w-12 text-left">{Number(item.value).toLocaleString("ar")}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function StatCard({ label, value, icon: Icon, color }: { label: string; value: number; icon: any; color: string }) {
  const colors: Record<string, string> = {
    indigo: "from-indigo-500/20 to-indigo-600/20 text-indigo-400",
    emerald: "from-emerald-500/20 to-emerald-600/20 text-emerald-400",
    amber: "from-amber-500/20 to-amber-600/20 text-amber-400",
    purple: "from-purple-500/20 to-purple-600/20 text-purple-400",
  };

  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
      <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${colors[color]} flex items-center justify-center mb-3`}>
        <Icon className="w-5 h-5" />
      </div>
      <p className="text-2xl font-bold">{value.toLocaleString("ar")}</p>
      <p className="text-sm text-gray-400 mt-1">{label}</p>
    </div>
  );
}

function SubscriberManagement() {
  const { data: subscribersData, refetch } = trpc.admin.subscriptions.getSubscribers.useQuery();
  const { data: plansData } = trpc.admin.plans.list.useQuery();
  const subscribers = subscribersData || [];
  const plans = plansData || [];

  const createSub = trpc.admin.subscriptions.create.useMutation({
    onSuccess: () => { toast.success("تم إضافة الاشتراك"); refetch(); },
    onError: (e: any) => toast.error(e.message),
  });
  const cancelSub = trpc.admin.subscriptions.cancel.useMutation({
    onSuccess: () => { toast.success("تم إلغاء الاشتراك"); refetch(); },
    onError: (e: any) => toast.error(e.message),
  });
  const extendSub = trpc.admin.subscriptions.extend.useMutation({
    onSuccess: () => { toast.success("تم تمديد الاشتراك"); refetch(); },
    onError: (e: any) => toast.error(e.message),
  });

  const [userId, setUserId] = useState("");
  const [planId, setPlanId] = useState("");
  const [duration, setDuration] = useState(30);
  const [search, setSearch] = useState("");

  const filtered = (subscribers as any[]).filter((s: any) =>
    !search ||
    s.user?.email?.toLowerCase().includes(search.toLowerCase()) ||
    s.user?.name?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <CreditCard className="w-5 h-5 text-purple-400" />
        إدارة المشتركين
      </h2>

      {/* Add Subscription */}
      <div className="p-5 rounded-xl border border-white/10 bg-white/[0.02] space-y-3">
        <h3 className="font-semibold text-sm text-gray-300">➕ إضافة اشتراك يدوي</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <input
            value={userId}
            onChange={e => setUserId(e.target.value)}
            placeholder="User ID (رقم)"
            className="px-3 py-2 rounded-lg border border-white/10 bg-white/5 text-sm focus:outline-none focus:border-indigo-500/50 col-span-2 md:col-span-1"
          />
          <select
            value={planId}
            onChange={e => setPlanId(e.target.value)}
            className="px-3 py-2 rounded-lg border border-white/10 bg-white/5 text-sm focus:outline-none focus:border-indigo-500/50"
          >
            <option value="">اختر الخطة...</option>
            {(plans as any[]).map((p: any) => (
              <option key={p.id} value={p.id}>{p.displayName || p.name}</option>
            ))}
          </select>
          <input
            type="number"
            value={duration}
            onChange={e => setDuration(Number(e.target.value))}
            min={1}
            max={365}
            placeholder="عدد الأيام"
            className="px-3 py-2 rounded-lg border border-white/10 bg-white/5 text-sm focus:outline-none focus:border-indigo-500/50"
          />
          <button
            onClick={() => {
              if (!userId || !planId) { toast.error("أدخل User ID والخطة"); return; }
              createSub.mutate({ userId: Number(userId), planId: Number(planId), durationDays: duration });
            }}
            className="px-4 py-2 rounded-lg bg-indigo-500 hover:bg-indigo-600 text-white text-sm font-medium transition-colors"
          >
            إضافة
          </button>
        </div>
      </div>

      {/* Subscribers List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-sm text-gray-300">
            المشتركون ({(subscribers as any[]).length})
          </h3>
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute right-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="بحث..."
              className="bg-white/5 border border-white/10 rounded-lg pr-9 pl-3 py-1.5 text-sm focus:outline-none focus:border-indigo-500/50 w-44"
            />
          </div>
        </div>

        <div className="space-y-2">
          {filtered.map((sub: any) => (
            <div
              key={sub.id}
              className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 transition-colors ${
                sub.isExpired
                  ? "border-red-500/20 bg-red-500/5"
                  : sub.daysLeft !== null && sub.daysLeft <= 7
                  ? "border-yellow-500/20 bg-yellow-500/5"
                  : "border-white/10 bg-white/[0.02]"
              }`}
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <div className="w-7 h-7 rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-xs font-bold shrink-0">
                    {((sub.user?.name || sub.user?.email || "?")[0] || "?").toUpperCase()}
                  </div>
                  <span className="text-sm font-medium">{sub.user?.name || sub.user?.email || `ID: ${sub.userId}`}</span>
                  <span className={`text-xs px-2 py-0.5 rounded-full border ${
                    sub.plan?.name === "pro"
                      ? "text-purple-400 bg-purple-400/10 border-purple-400/20"
                      : "text-blue-400 bg-blue-400/10 border-blue-400/20"
                  }`}>
                    {sub.plan?.displayName || sub.plan?.name || "—"}
                  </span>
                  {sub.isExpired && (
                    <span className="text-xs text-red-400 bg-red-400/10 px-2 py-0.5 rounded-full border border-red-400/20">منتهي</span>
                  )}
                  {!sub.isExpired && sub.daysLeft !== null && sub.daysLeft <= 7 && (
                    <span className="text-xs text-yellow-400 bg-yellow-400/10 px-2 py-0.5 rounded-full border border-yellow-400/20">
                      ينتهي خلال {sub.daysLeft} يوم
                    </span>
                  )}
                </div>
                <p className="text-xs text-gray-500 mt-1 mr-9">
                  {sub.daysLeft !== null ? `${sub.daysLeft} يوم متبقي` : "غير محدود"} •
                  {" "}تاريخ الانتهاء:{" "}
                  {sub.endDate ? new Date(sub.endDate).toLocaleDateString("ar-SA") : "—"} •
                  {" "}الحالة: {sub.status}
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => extendSub.mutate({ subscriptionId: sub.id, extraDays: 30 })}
                  className="px-3 py-1.5 text-xs rounded-lg bg-green-500/10 text-green-400 border border-green-500/20 hover:bg-green-500/20 disabled:opacity-50 transition-colors"
                >
                  +30 يوم
                </button>
                {sub.status === "active" && (
                  <button
                    onClick={() => {
                      if (confirm(`إلغاء اشتراك ${sub.user?.name || sub.userId}؟`)) {
                        cancelSub.mutate({ subscriptionId: sub.id });
                      }
                    }}
                    className="px-3 py-1.5 text-xs rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 disabled:opacity-50 transition-colors"
                  >
                    إلغاء
                  </button>
                )}
              </div>
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="text-center py-12 text-gray-500">
              <CreditCard className="w-12 h-12 mx-auto mb-3 opacity-30" />
              <p>{search ? "لا توجد نتائج للبحث" : "لا يوجد مشتركون حالياً"}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
