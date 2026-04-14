import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { getLoginUrl } from "@/const";
import { Link, useSearch, useLocation } from "wouter";
import {
  ArrowLeft, Copy, Check, Mail, MessageCircle,
  Shield, Clock, Zap, Crown, Rocket, KeyRound, Sparkles, Building2,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import { toast } from "sonner";
import { useState, useCallback } from "react";

const HAYO_LOGO = `${import.meta.env.BASE_URL ?? "/"}logo.png`;

// Payment methods configuration
const PAYMENT_METHODS = {
  paypal: {
    label: "PayPal",
    icon: "💳",
    address: "fmf0038@gmail.com",
    color: "from-blue-500 to-blue-700",
    bgColor: "bg-blue-500/10 border-blue-500/20",
    instructions: "أرسل المبلغ إلى حساب PayPal أدناه مع ذكر اسم الخطة في ملاحظات الدفع",
  },
  usdt_erc20: {
    label: "USDT (ERC-20)",
    icon: "🟢",
    address: "0x787e6625657cc8f410A3B233a21c0fa9D34664B0",
    color: "from-emerald-500 to-teal-600",
    bgColor: "bg-emerald-500/10 border-emerald-500/20",
    instructions: "أرسل USDT عبر شبكة Ethereum (ERC-20) إلى العنوان أدناه",
  },
  usdt_trc20: {
    label: "USDT (TRC-20)",
    icon: "🔴",
    address: "TX92pAkYgq2BtSYbjgqrN4nrXfLJ73yFAy",
    color: "from-red-500 to-rose-600",
    bgColor: "bg-red-500/10 border-red-500/20",
    instructions: "أرسل USDT عبر شبكة TRON (TRC-20) إلى العنوان أدناه - رسوم أقل",
  },
  bitcoin: {
    label: "Bitcoin (BTC)",
    icon: "₿",
    address: "3DDVW84radoB6xtAiavkC5KEvditSQcRVx",
    color: "from-orange-500 to-amber-600",
    bgColor: "bg-orange-500/10 border-orange-500/20",
    instructions: "أرسل Bitcoin إلى العنوان أدناه",
  },
  ethereum: {
    label: "Ethereum (ETH)",
    icon: "⟠",
    address: "0x787e6625657cc8f410A3B233a21c0fa9D34664B0",
    color: "from-indigo-500 to-purple-600",
    bgColor: "bg-indigo-500/10 border-indigo-500/20",
    instructions: "أرسل Ethereum إلى العنوان أدناه",
  },
};

type PaymentMethodKey = keyof typeof PAYMENT_METHODS;

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success("تم النسخ!");
    setTimeout(() => setCopied(false), 2000);
  }, [text]);
  return (
    <button
      onClick={handleCopy}
      className="p-2 rounded-lg hover:bg-white/10 transition-colors"
      title="نسخ"
    >
      {copied ? <Check className="size-4 text-emerald-400" /> : <Copy className="size-4 text-gray-400" />}
    </button>
  );
}

export default function Payment() {
  const { user, isAuthenticated } = useAuth();
  const searchString = useSearch();
  const [, navigate] = useLocation();
  const params = new URLSearchParams(searchString);
  const planName = params.get("plan") || "basic";
  const { data: plans } = trpc.plans.list.useQuery();

  const selectedPlan = plans?.find((p: any) => p.name === planName);
  const price = selectedPlan ? (selectedPlan.priceMonthly / 100).toFixed(0) : planName === "pro" ? "49" : "19";
  const displayName = selectedPlan?.displayName || (planName === "pro" ? "الاحترافي" : "الأساسي");

  const planIcons: Record<string, any> = { free: Zap, basic: Crown, starter: Crown, pro: Rocket, business: Building2 };
  const PlanIcon = planIcons[planName] || Crown;

  const billingPeriod = params.get("billing") || "monthly";
  const yearlyPrice = selectedPlan ? (selectedPlan.priceYearly / 100).toFixed(2) : "0";
  const monthlyPrice = selectedPlan ? (selectedPlan.priceMonthly / 100).toFixed(2) : "0";
  const displayPrice = billingPeriod === "yearly" ? yearlyPrice : monthlyPrice;

  const [selectedMethod, setSelectedMethod] = useState<PaymentMethodKey | null>(null);
  const [redeemCode, setRedeemCode] = useState("");
  const [showRedeemSection, setShowRedeemSection] = useState(false);
  const [stripeLoading, setStripeLoading] = useState(false);

  // Stripe checkout
  const stripeCheckoutMut = trpc.subscriptions.createStripeCheckout.useMutation({
    onSuccess: (data: any) => {
      if (data.url) {
        window.location.href = data.url;
      } else {
        toast.error("فشل إنشاء جلسة الدفع");
      }
      setStripeLoading(false);
    },
    onError: (err: any) => {
      toast.error(err.message || "فشل الاتصال بـ Stripe");
      setStripeLoading(false);
    },
  });

  const handleStripeCheckout = () => {
    if (!["starter", "pro", "business"].includes(planName)) {
      toast.error("الخطة المجانية لا تحتاج دفع");
      return;
    }
    setStripeLoading(true);
    stripeCheckoutMut.mutate({
      planName: planName as "starter" | "pro" | "business",
      billingPeriod: billingPeriod as "monthly" | "yearly",
    });
  };

  // Auto-verify stripe payment on success redirect
  const stripeSessionId = params.get("session_id");
  const stripeVerifyMut = trpc.subscriptions.verifyStripePayment.useMutation({
    onSuccess: (data: any) => {
      if (data.success) {
        toast.success(`🎉 تم تفعيل اشتراك ${data.plan.displayName} بنجاح!`, { duration: 8000 });
      }
    },
  });
  if (stripeSessionId && params.get("status") === "success" && !stripeVerifyMut.isSuccess && !stripeVerifyMut.isPending) {
    stripeVerifyMut.mutate({ sessionId: stripeSessionId });
  }

  const redeemMutation = trpc.subscriptions.redeem.useMutation({
    onSuccess: (data: any) => {
      toast.success(`🎉 تم تفعيل اشتراك ${data.plan.displayName} بنجاح!`, {
        description: `ينتهي بتاريخ ${new Date(data.expiresAt).toLocaleDateString("ar-SA")}`,
        duration: 6000,
      });
      setTimeout(() => navigate("/chat"), 2000);
    },
    onError: (err: any) => {
      toast.error("خطأ في الكود", { description: err.message });
    },
  });

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#0a0a0f] text-white flex items-center justify-center">
        <div className="text-center space-y-6 max-w-md px-4">
          <img src={HAYO_LOGO} alt="HAYO AI" className="w-16 h-16 rounded-2xl mx-auto shadow-lg shadow-indigo-500/25" />
          <h1 className="text-2xl font-bold">سجّل دخولك للاشتراك</h1>
          <p className="text-gray-400">يجب تسجيل الدخول أولاً لإتمام عملية الاشتراك</p>
          <a href={getLoginUrl()}>
            <Button size="lg" className="bg-gradient-to-r from-indigo-500 to-purple-600 text-white">
              تسجيل الدخول
            </Button>
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white" dir="rtl">
      {/* Header */}
      <header className="border-b border-white/5 bg-[#0a0a0f]/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-5xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/pricing" className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors">
            <ArrowLeft className="size-4" />
            <span className="text-sm">العودة للأسعار</span>
          </Link>
          <Link href="/" className="flex items-center gap-2">
            <img src={HAYO_LOGO} alt="HAYO AI" className="w-8 h-8 rounded-lg" />
            <span className="font-bold">HAYO AI</span>
          </Link>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-6 py-12">
        {/* Plan Summary */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-3 bg-white/5 border border-white/10 rounded-2xl px-6 py-4 mb-6">
            <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${planName === "pro" ? "from-amber-500 to-orange-600" : "from-indigo-500 to-purple-600"} flex items-center justify-center`}>
              <PlanIcon className="size-6 text-white" />
            </div>
            <div className="text-right">
              <p className="text-sm text-gray-400">الخطة المختارة</p>
              <p className="text-xl font-bold">{displayName} - ${displayPrice}<span className="text-sm text-gray-400 font-normal">/{billingPeriod === "yearly" ? "سنة" : "شهر"}</span></p>
            </div>
          </div>
          <h1 className="text-3xl font-bold mb-3">إتمام الاشتراك</h1>
          <p className="text-gray-400 max-w-lg mx-auto">
            اختر طريقة الدفع المناسبة لك — Stripe (تلقائي فوري) أو يدوي (تفعيل خلال 24 ساعة).
          </p>
        </div>

        {/* Stripe Success */}
        {stripeVerifyMut.isSuccess && (
          <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-2xl p-6 text-center mb-8 space-y-3">
            <Check className="w-12 h-12 text-emerald-400 mx-auto" />
            <h2 className="text-xl font-bold text-emerald-400">تم تفعيل اشتراكك بنجاح! 🎉</h2>
            <p className="text-sm text-gray-300">يمكنك الآن استخدام جميع ميزات خطتك</p>
            <Link href="/chat"><Button className="bg-emerald-600 hover:bg-emerald-700 gap-2">ابدأ الآن ←</Button></Link>
          </div>
        )}

        {/* ═══ Stripe — Automatic Payment ═══ */}
        <div className="bg-gradient-to-r from-violet-500/5 to-indigo-500/5 border border-violet-500/20 rounded-2xl p-6 mb-8 space-y-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center">
              <Sparkles className="w-5 h-5 text-white" />
            </div>
            <div>
              <h3 className="font-bold text-lg">💳 الدفع التلقائي — Stripe</h3>
              <p className="text-xs text-gray-400">بطاقة ائتمان / خصم — تفعيل فوري</p>
            </div>
            <div className="mr-auto text-left">
              <p className="text-2xl font-bold">${displayPrice}</p>
              <p className="text-[10px] text-gray-400">{billingPeriod === "yearly" ? "سنوي" : "شهري"}</p>
            </div>
          </div>
          <Button
            onClick={handleStripeCheckout}
            disabled={stripeLoading || stripeCheckoutMut.isPending}
            className="w-full py-5 text-base gap-2 bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-500 hover:to-indigo-500"
          >
            {stripeLoading ? (
              <><Clock className="w-5 h-5 animate-spin" /> جاري التوجيه لـ Stripe...</>
            ) : (
              <><Shield className="w-5 h-5" /> ادفع ${displayPrice} بالبطاقة — تفعيل فوري</>
            )}
          </Button>
          <p className="text-[10px] text-gray-500 text-center">مدعوم من Stripe — آمن ومشفر</p>
        </div>

        {/* ═══ Manual Payment Methods ═══ */}
        <div className="mb-4">
          <h3 className="text-sm font-bold text-gray-400 mb-3">أو الدفع اليدوي (تفعيل خلال 24 ساعة):</h3>
        </div>

        {/* Payment Methods Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-10">
          {(Object.keys(PAYMENT_METHODS) as PaymentMethodKey[]).map((key) => {
            const method = PAYMENT_METHODS[key];
            const isSelected = selectedMethod === key;
            return (
              <button
                key={key}
                onClick={() => setSelectedMethod(isSelected ? null : key)}
                className={`p-5 rounded-2xl border text-right transition-all duration-300 ${
                  isSelected
                    ? `${method.bgColor} border-2 scale-[1.02] shadow-lg`
                    : "bg-white/[0.03] border-white/10 hover:bg-white/[0.06] hover:border-white/20"
                }`}
              >
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-2xl">{method.icon}</span>
                  <span className="font-semibold text-lg">{method.label}</span>
                </div>
                <p className="text-sm text-gray-400">{method.instructions}</p>
              </button>
            );
          })}
        </div>

        {/* Selected Payment Method Details */}
        {selectedMethod && (
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
            <Card className="bg-white/[0.03] border-white/10 mb-10">
              <CardHeader className="pb-4">
                <CardTitle className="flex items-center gap-3 text-xl">
                  <span className="text-2xl">{PAYMENT_METHODS[selectedMethod].icon}</span>
                  الدفع عبر {PAYMENT_METHODS[selectedMethod].label}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Amount */}
                <div className="bg-white/5 rounded-xl p-4 flex items-center justify-between">
                  <span className="text-gray-400">المبلغ المطلوب</span>
                  <span className="text-2xl font-bold text-white">${price} USD</span>
                </div>

                {/* Address */}
                <div>
                  <label className="text-sm text-gray-400 mb-2 block">
                    {selectedMethod === "paypal" ? "حساب PayPal" : "عنوان المحفظة"}
                  </label>
                  <div className="bg-black/40 border border-white/10 rounded-xl p-4 flex items-center gap-3">
                    <code className="flex-1 text-sm font-mono text-emerald-400 break-all select-all">
                      {PAYMENT_METHODS[selectedMethod].address}
                    </code>
                    <CopyButton text={PAYMENT_METHODS[selectedMethod].address} />
                  </div>
                </div>

                {/* Instructions */}
                <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4">
                  <h4 className="font-semibold text-amber-400 mb-2 flex items-center gap-2">
                    <Shield className="size-4" />
                    تعليمات مهمة
                  </h4>
                  <ul className="space-y-2 text-sm text-gray-300">
                    <li className="flex items-start gap-2">
                      <span className="text-amber-400 mt-0.5">1.</span>
                      أرسل المبلغ <strong className="text-white">${price} USD</strong> بالضبط إلى العنوان أعلاه
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-400 mt-0.5">2.</span>
                      {selectedMethod === "paypal"
                        ? "اكتب في ملاحظات الدفع: اسمك + الخطة المختارة"
                        : "احتفظ بـ Transaction Hash (معرّف المعاملة)"}
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-400 mt-0.5">3.</span>
                      تواصل معنا عبر أحد الطرق أدناه لتأكيد الدفع وتفعيل اشتراكك
                    </li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Contact for Activation */}
        <Card className="bg-gradient-to-br from-indigo-500/10 to-purple-500/10 border-indigo-500/20 mb-10">
          <CardContent className="py-8">
            <h3 className="text-xl font-bold text-center mb-6">تواصل معنا لتفعيل اشتراكك</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-lg mx-auto">
              <a
                href="mailto:fmf0038@gmail.com?subject=HAYO AI Subscription - ${planName}&body=مرحباً، أريد الاشتراك في خطة ${displayName}"
                className="flex items-center gap-3 bg-white/5 border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-colors"
              >
                <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center">
                  <Mail className="size-5 text-blue-400" />
                </div>
                <div>
                  <p className="font-semibold text-sm">البريد الإلكتروني</p>
                  <p className="text-xs text-gray-400">fmf0038@gmail.com</p>
                </div>
              </a>
              <a
                href="https://t.me/fmf0038"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-3 bg-white/5 border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-colors"
              >
                <div className="w-10 h-10 rounded-lg bg-sky-500/20 flex items-center justify-center">
                  <MessageCircle className="size-5 text-sky-400" />
                </div>
                <div>
                  <p className="font-semibold text-sm">تلغرام</p>
                  <p className="text-xs text-gray-400">@fmf0038</p>
                </div>
              </a>
            </div>
            <p className="text-center text-sm text-gray-400 mt-6">
              <Clock className="size-4 inline-block ml-1" />
              يتم تفعيل الاشتراك خلال 24 ساعة من تأكيد الدفع
            </p>
          </CardContent>
        </Card>

        {/* ───── Code Redemption Section ───── */}
        <div className="mb-10">
          <button
            onClick={() => setShowRedeemSection(!showRedeemSection)}
            className="w-full flex items-center justify-between p-5 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/15 transition-all duration-300 group"
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/20 flex items-center justify-center">
                <KeyRound className="size-5 text-emerald-400" />
              </div>
              <div className="text-right">
                <p className="font-bold text-emerald-400">لديك كود اشتراك؟</p>
                <p className="text-sm text-gray-400">أدخل الكود الذي أرسله لك المدير لتفعيل اشتراكك فوراً</p>
              </div>
            </div>
            <span className="text-emerald-400 text-lg group-hover:scale-110 transition-transform">
              {showRedeemSection ? "▲" : "▼"}
            </span>
          </button>

          {showRedeemSection && (
            <div className="mt-4 animate-in fade-in slide-in-from-top-2 duration-300">
              <Card className="bg-white/[0.03] border-emerald-500/20">
                <CardContent className="pt-6">
                  <div className="space-y-4">
                    <div>
                      <label className="text-sm text-gray-400 mb-2 block">كود الاشتراك</label>
                      <div className="flex gap-3">
                        <Input
                          value={redeemCode}
                          onChange={(e) => setRedeemCode(e.target.value.toUpperCase())}
                          placeholder="HAYO-XXXXXX-XXXXXX"
                          className="flex-1 bg-black/40 border-white/20 text-white font-mono text-center text-lg tracking-widest"
                          maxLength={20}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && redeemCode.length >= 8) {
                              redeemMutation.mutate({ code: redeemCode });
                            }
                          }}
                        />
                        <Button
                          onClick={() => redeemMutation.mutate({ code: redeemCode })}
                          disabled={redeemCode.length < 8 || redeemMutation.isPending}
                          className="bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700 min-w-[100px]"
                        >
                          {redeemMutation.isPending ? (
                            <span className="animate-spin">⏳</span>
                          ) : (
                            <>
                              <Sparkles className="size-4 ml-1" />
                              تفعيل
                            </>
                          )}
                        </Button>
                      </div>
                      <p className="text-xs text-gray-500 mt-2">
                        مثال: HAYO-A1B2C3-D4E5F6 — الكود يفعّل اشتراكك لمدة شهر كامل
                      </p>
                    </div>

                    {redeemMutation.isError && (
                      <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                        ❌ {redeemMutation.error?.message || "الكود غير صحيح"}
                      </div>
                    )}

                    {redeemMutation.isSuccess && (
                      <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-sm">
                        ✅ تم تفعيل اشتراكك! جارٍ تحويلك للدردشة...
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </div>

        {/* Security Note */}
        <div className="text-center text-sm text-gray-500 space-y-2 pb-12">
          <div className="flex items-center justify-center gap-2">
            <Shield className="size-4 text-emerald-500" />
            <span>جميع المعاملات آمنة ومشفرة</span>
          </div>
          <p>
            بحاجة لمساعدة؟{" "}
            <a href="mailto:fmf0038@gmail.com" className="text-indigo-400 hover:underline">تواصل معنا</a>
          </p>
        </div>
      </div>
    </div>
  );
}
