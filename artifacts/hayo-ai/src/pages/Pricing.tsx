import { useState } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { getLoginUrl } from "@/const";
import { Link } from "wouter";
import { Check, X, Zap, Crown, Rocket, Building2, ArrowRight, Shield, Star } from "lucide-react";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import { toast } from "sonner";

const HAYO_LOGO = `${import.meta.env.BASE_URL ?? "/"}logo.png`;

const PLANS = [
  {
    name: "free", displayName: "تجريبي", icon: Zap, emoji: "🆓",
    gradient: "from-slate-500 to-slate-600", border: "border-slate-500/30",
    priceMonthly: 0, priceYearly: 0,
    tagline: "تجربة لمرة واحدة — 3 أيام",
    limits: {
      dailyCredits: 10, monthlyCredits: 30,
      models: ["Haiku"],
      pipelines: 1, battles: 1,
      upload: "5 MB", studies: 1, office: 2, ea: 0, trading: 0,
      sandbox: false, webSearch: false, imageGen: false, fileCreation: false, priority: false,
    },
  },
  {
    name: "starter", displayName: "المبتدئ", icon: Crown, emoji: "⭐",
    gradient: "from-indigo-500 to-purple-600", border: "border-indigo-500/30",
    priceMonthly: 9.99, priceYearly: 95.88,
    tagline: "للاستخدام الشخصي والطلاب",
    popular: false,
    limits: {
      dailyCredits: 25, monthlyCredits: 500,
      models: ["Haiku", "Sonnet"],
      pipelines: 3, battles: 5,
      upload: "15 MB", studies: 10, office: 20, ea: 3, trading: 5,
      sandbox: false, webSearch: true, imageGen: false, fileCreation: true, priority: false,
    },
  },
  {
    name: "pro", displayName: "الاحترافي", icon: Rocket, emoji: "🚀",
    gradient: "from-amber-500 to-orange-600", border: "border-amber-500/30",
    priceMonthly: 29.99, priceYearly: 287.88,
    tagline: "للمحترفين — كل الميزات",
    popular: true,
    limits: {
      dailyCredits: 100, monthlyCredits: 2000,
      models: ["Haiku", "Sonnet", "Opus"],
      pipelines: 30, battles: 30,
      upload: "50 MB", studies: 50, office: "∞", ea: 20, trading: 30,
      sandbox: true, webSearch: true, imageGen: true, fileCreation: true, priority: false,
    },
  },
  {
    name: "business", displayName: "الأعمال", icon: Building2, emoji: "🏢",
    gradient: "from-violet-600 to-fuchsia-600", border: "border-violet-500/30",
    priceMonthly: 79.99, priceYearly: 767.88,
    tagline: "للشركات والفرق الكبيرة",
    limits: {
      dailyCredits: 400, monthlyCredits: 8000,
      models: ["Haiku", "Sonnet", "Opus"],
      pipelines: 200, battles: "∞",
      upload: "100 MB", studies: "∞", office: "∞", ea: "∞", trading: "∞",
      sandbox: true, webSearch: true, imageGen: true, fileCreation: true, priority: true,
    },
  },
];

const FEATURES = [
  { label: "نقاط يومية", key: "dailyCredits" },
  { label: "نقاط شهرية", key: "monthlyCredits" },
  { label: "نماذج AI", key: "models", isArray: true },
  { label: "وكيل الكود (pipelines)", key: "pipelines" },
  { label: "غرفة المعارك", key: "battles" },
  { label: "حجم الرفع", key: "upload" },
  { label: "دراسات / شهر", key: "studies" },
  { label: "أدوات مكتبية / شهر", key: "office" },
  { label: "EA Factory / شهر", key: "ea" },
  { label: "تحليل تداول / شهر", key: "trading" },
  { label: "بحث ويب", key: "webSearch", isBool: true },
  { label: "توليد صور", key: "imageGen", isBool: true },
  { label: "إنشاء ملفات", key: "fileCreation", isBool: true },
  { label: "بيئة تنفيذ Sandbox", key: "sandbox", isBool: true },
  { label: "دعم أولوية", key: "priority", isBool: true },
];

export default function Pricing() {
  const { isAuthenticated } = useAuth();
  const { data: usageData } = trpc.usage.subscription.useQuery(undefined, { enabled: isAuthenticated });
  const [billing, setBilling] = useState<"monthly" | "yearly">("monthly");

  const currentPlan = usageData?.plan?.name || "free";

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white" dir="rtl">
      {/* Header */}
      <header className="border-b border-white/5 bg-[#0a0a0f]/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3">
            <img src={HAYO_LOGO} alt="HAYO AI" className="w-9 h-9 rounded-lg" />
            <span className="text-lg font-bold">HAYO AI</span>
          </Link>
          <div className="flex items-center gap-4">
            <Link href="/chat"><Button variant="ghost" size="sm">الدردشة</Button></Link>
            {isAuthenticated ? (
              <Link href="/account"><Button size="sm" className="bg-gradient-to-r from-indigo-500 to-purple-600">حسابي</Button></Link>
            ) : (
              <a href={getLoginUrl()}><Button size="sm" className="bg-gradient-to-r from-indigo-500 to-purple-600">تسجيل الدخول</Button></a>
            )}
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="py-16 text-center">
        <div className="max-w-4xl mx-auto px-6">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-indigo-500/10 border border-indigo-500/20 mb-6">
            <Shield className="w-4 h-4 text-indigo-400" />
            <span className="text-sm text-indigo-300">خطط مرنة — ادفع حسب احتياجك</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold mb-4">
            اختر خطتك <span className="bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">المثالية</span>
          </h1>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto mb-8">
            22+ أداة AI — دردشة، وكيل كود، دراسات، تداول، EA Factory، أعمال مكتبية، وأكثر
          </p>

          {/* Billing Toggle */}
          <div className="inline-flex items-center bg-white/5 rounded-xl p-1 border border-white/10">
            <button onClick={() => setBilling("monthly")} className={`px-6 py-2.5 rounded-lg text-sm font-medium transition-all ${billing === "monthly" ? "bg-indigo-500 text-white shadow" : "text-gray-400"}`}>
              شهري
            </button>
            <button onClick={() => setBilling("yearly")} className={`px-6 py-2.5 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${billing === "yearly" ? "bg-indigo-500 text-white shadow" : "text-gray-400"}`}>
              سنوي <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded-full">وفّر 20%</span>
            </button>
          </div>
        </div>
      </section>

      {/* Plans Grid */}
      <section className="pb-12">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
            {PLANS.map(plan => {
              const Icon = plan.icon;
              const isCurrent = currentPlan === plan.name;
              const price = billing === "yearly" ? plan.priceYearly : plan.priceMonthly;
              const monthlyEquiv = billing === "yearly" && plan.priceYearly > 0 ? (plan.priceYearly / 12).toFixed(2) : null;

              return (
                <div key={plan.name} className={`relative rounded-2xl border p-6 flex flex-col ${plan.popular ? "border-amber-500/50 bg-amber-500/5 ring-1 ring-amber-500/20" : "border-white/10 bg-white/[0.02]"}`}>
                  {plan.popular && (
                    <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-gradient-to-r from-amber-500 to-orange-500 text-white text-xs font-bold px-4 py-1 rounded-full flex items-center gap-1">
                      <Star className="w-3 h-3" /> الأكثر شعبية
                    </div>
                  )}
                  {isCurrent && (
                    <div className="absolute -top-3 right-4 bg-emerald-500 text-white text-xs font-bold px-3 py-1 rounded-full">خطتك الحالية</div>
                  )}

                  <div className="flex items-center gap-3 mb-4">
                    <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${plan.gradient} flex items-center justify-center`}>
                      <Icon className="w-5 h-5 text-white" />
                    </div>
                    <div>
                      <h3 className="font-bold text-lg">{plan.displayName}</h3>
                      <p className="text-xs text-gray-400">{plan.tagline}</p>
                    </div>
                  </div>

                  <div className="mb-6">
                    <div className="flex items-baseline gap-1">
                      <span className="text-3xl font-bold">${price === 0 ? "0" : billing === "yearly" ? monthlyEquiv : price.toFixed(2)}</span>
                      {price > 0 && <span className="text-sm text-gray-400">/شهر</span>}
                    </div>
                    {billing === "yearly" && price > 0 && (
                      <p className="text-xs text-emerald-400 mt-1">${plan.priceYearly.toFixed(2)}/سنة — وفّر ${(plan.priceMonthly * 12 - plan.priceYearly).toFixed(0)}$</p>
                    )}
                    {price === 0 && <p className="text-xs text-amber-400 mt-1">3 أيام فقط — لمرة واحدة</p>}
                  </div>

                  {/* Key Limits */}
                  <div className="space-y-2 flex-1 mb-6">
                    <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> <span>{plan.limits.dailyCredits} نقطة/يوم — {plan.limits.monthlyCredits}/شهر</span></div>
                    <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> <span>نماذج: {plan.limits.models.join(" + ")}</span></div>
                    <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> <span>{plan.limits.pipelines} خط أنابيب وكيل</span></div>
                    <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> <span>{plan.limits.battles} معركة WarRoom</span></div>
                    <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> <span>رفع ملفات حتى {plan.limits.upload}</span></div>
                    {plan.limits.webSearch ? (
                      <div className="flex items-center gap-2 text-sm"><Check className="w-4 h-4 text-emerald-400 shrink-0" /> بحث ويب</div>
                    ) : (
                      <div className="flex items-center gap-2 text-sm text-gray-500"><X className="w-4 h-4 shrink-0" /> بحث ويب</div>
                    )}
                    {plan.limits.priority && (
                      <div className="flex items-center gap-2 text-sm text-amber-400"><Crown className="w-4 h-4 shrink-0" /> دعم أولوية</div>
                    )}
                  </div>

                  {/* CTA */}
                  {plan.name === "free" ? (
                    <Button variant="outline" className="w-full" disabled={isCurrent}>
                      {isCurrent ? "خطتك الحالية" : "ابدأ مجاناً"}
                    </Button>
                  ) : (
                    <Link href={`/payment?plan=${plan.name}&billing=${billing}`}>
                      <Button className={`w-full gap-2 bg-gradient-to-r ${plan.gradient}`}>
                        {isCurrent ? "خطتك الحالية" : <><span>اشترك الآن</span> <ArrowRight className="w-4 h-4" /></>}
                      </Button>
                    </Link>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Feature Comparison Table */}
      <section className="pb-20">
        <div className="max-w-7xl mx-auto px-6">
          <h2 className="text-2xl font-bold text-center mb-8">مقارنة تفصيلية للخطط</h2>
          <div className="overflow-x-auto rounded-2xl border border-white/10">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-white/5">
                  <th className="text-right px-6 py-4 font-medium text-gray-400">الميزة</th>
                  {PLANS.map(p => (
                    <th key={p.name} className="px-4 py-4 text-center font-bold">{p.emoji} {p.displayName}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {FEATURES.map((f, i) => (
                  <tr key={f.key} className={i % 2 === 0 ? "bg-white/[0.02]" : ""}>
                    <td className="px-6 py-3 text-gray-300 font-medium">{f.label}</td>
                    {PLANS.map(p => {
                      const val = (p.limits as any)[f.key];
                      return (
                        <td key={p.name} className="px-4 py-3 text-center">
                          {f.isBool ? (
                            val ? <Check className="w-4 h-4 text-emerald-400 mx-auto" /> : <X className="w-4 h-4 text-gray-600 mx-auto" />
                          ) : f.isArray ? (
                            <span className="text-xs">{val.join(", ")}</span>
                          ) : (
                            <span className={`font-medium ${val === "∞" ? "text-emerald-400" : val === 0 ? "text-gray-600" : "text-white"}`}>{val}</span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Credit Costs */}
      <section className="pb-20">
        <div className="max-w-4xl mx-auto px-6">
          <h2 className="text-2xl font-bold text-center mb-4">تكلفة كل عملية بالنقاط</h2>
          <p className="text-center text-gray-400 text-sm mb-8">كل عملية تستهلك عدداً محدداً من النقاط من رصيدك اليومي</p>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {[
              { op: "دردشة AI", cost: 2 }, { op: "وكيل الكود (pipeline)", cost: 30 },
              { op: "غرفة المعارك", cost: 10 }, { op: "PowerPoint", cost: 8 },
              { op: "Word Report", cost: 8 }, { op: "Excel Processing", cost: 3 },
              { op: "دراسة كاملة", cost: 15 }, { op: "EA Factory — تحليل", cost: 10 },
              { op: "EA Factory — توليد", cost: 15 }, { op: "تحليل تداول", cost: 5 },
              { op: "مصنع البرومبت", cost: 5 }, { op: "بناء تطبيق APK", cost: 15 },
            ].map(item => (
              <div key={item.op} className="flex items-center justify-between bg-white/5 border border-white/10 rounded-xl px-4 py-3">
                <span className="text-xs text-gray-300">{item.op}</span>
                <span className="text-sm font-bold text-indigo-400">{item.cost} 💎</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
