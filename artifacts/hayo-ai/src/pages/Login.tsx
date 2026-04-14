import { useState } from "react";
import { useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loader2, Brain, KeyRound, MessageCircle, Mail, X } from "lucide-react";
import { toast } from "sonner";

const HAYO_LOGO = `${import.meta.env.BASE_URL ?? "/"}logo.png`;

export default function Login() {
  const [, navigate] = useLocation();
  const utils = trpc.useUtils();

  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [registerName, setRegisterName] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [showForgot, setShowForgot] = useState(false);

  const loginMutation = trpc.auth.login.useMutation({
    onSuccess: () => {
      utils.auth.me.invalidate();
      navigate("/dashboard");
      toast.success("تم تسجيل الدخول بنجاح");
    },
    onError: (err: any) => {
      toast.error(err.message || "فشل تسجيل الدخول");
    },
  });

  const registerMutation = trpc.auth.register.useMutation({
    onSuccess: () => {
      utils.auth.me.invalidate();
      navigate("/dashboard");
      toast.success("تم إنشاء الحساب بنجاح");
    },
    onError: (err: any) => {
      toast.error(err.message || "فشل إنشاء الحساب");
    },
  });

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginEmail || !loginPassword) return;
    loginMutation.mutate({ email: loginEmail, password: loginPassword });
  };

  const handleRegister = (e: React.FormEvent) => {
    e.preventDefault();
    if (!registerEmail || !registerPassword || !registerName) return;
    registerMutation.mutate({ name: registerName, email: registerEmail, password: registerPassword });
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4" dir="rtl">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center">
          <img src={HAYO_LOGO} alt="HAYO AI" className="h-12 mx-auto mb-4" onError={(e) => { e.currentTarget.style.display = 'none'; }} />
          <div className="flex items-center justify-center gap-2 mb-2">
            <Brain className="h-8 w-8 text-primary" />
            <h1 className="text-3xl font-bold text-foreground">HAYO AI</h1>
          </div>
          <p className="text-muted-foreground">منصة الذكاء الاصطناعي المتقدمة</p>
        </div>

        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-center text-foreground">الدخول إلى حسابك</CardTitle>
            <CardDescription className="text-center text-muted-foreground">
              سجل دخولك أو أنشئ حساباً جديداً للبدء
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="login" dir="rtl">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="login">تسجيل الدخول</TabsTrigger>
                <TabsTrigger value="register">حساب جديد</TabsTrigger>
              </TabsList>

              {/* ─── Login Tab ─── */}
              <TabsContent value="login" className="space-y-4 mt-4">
                <form onSubmit={handleLogin} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="login-email">البريد الإلكتروني</Label>
                    <Input
                      id="login-email"
                      type="email"
                      placeholder="email@example.com"
                      value={loginEmail}
                      onChange={(e) => setLoginEmail(e.target.value)}
                      dir="ltr"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="login-password">كلمة المرور</Label>
                      <button
                        type="button"
                        onClick={() => setShowForgot(true)}
                        className="text-xs text-primary hover:underline focus:outline-none"
                      >
                        نسيت كلمة المرور؟
                      </button>
                    </div>
                    <Input
                      id="login-password"
                      type="password"
                      placeholder="••••••••"
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      dir="ltr"
                      required
                    />
                  </div>
                  <Button
                    type="submit"
                    className="w-full"
                    disabled={loginMutation.isPending}
                  >
                    {loginMutation.isPending ? (
                      <><Loader2 className="ml-2 h-4 w-4 animate-spin" />جاري الدخول...</>
                    ) : "تسجيل الدخول"}
                  </Button>
                </form>
              </TabsContent>

              {/* ─── Register Tab ─── */}
              <TabsContent value="register" className="space-y-4 mt-4">
                <form onSubmit={handleRegister} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="reg-name">الاسم</Label>
                    <Input
                      id="reg-name"
                      type="text"
                      placeholder="اسمك الكامل"
                      value={registerName}
                      onChange={(e) => setRegisterName(e.target.value)}
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="reg-email">البريد الإلكتروني</Label>
                    <Input
                      id="reg-email"
                      type="email"
                      placeholder="email@example.com"
                      value={registerEmail}
                      onChange={(e) => setRegisterEmail(e.target.value)}
                      dir="ltr"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="reg-password">كلمة المرور</Label>
                    <Input
                      id="reg-password"
                      type="password"
                      placeholder="••••••••"
                      value={registerPassword}
                      onChange={(e) => setRegisterPassword(e.target.value)}
                      dir="ltr"
                      required
                    />
                  </div>
                  <Button
                    type="submit"
                    className="w-full"
                    disabled={registerMutation.isPending}
                  >
                    {registerMutation.isPending ? (
                      <><Loader2 className="ml-2 h-4 w-4 animate-spin" />جاري الإنشاء...</>
                    ) : "إنشاء حساب"}
                  </Button>
                </form>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        {/* ─── Forgot Password Modal ─── */}
        {showForgot && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
            onClick={() => setShowForgot(false)}
          >
            <div
              className="bg-card border border-border rounded-2xl p-6 w-full max-w-sm space-y-5 shadow-2xl"
              dir="rtl"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="bg-primary/10 p-2 rounded-xl">
                    <KeyRound className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-foreground text-base">نسيت كلمة المرور؟</h3>
                    <p className="text-xs text-muted-foreground mt-0.5">تواصل مع الدعم لاسترداد حسابك</p>
                  </div>
                </div>
                <button
                  onClick={() => setShowForgot(false)}
                  className="text-muted-foreground hover:text-foreground transition-colors p-1 rounded-lg hover:bg-muted"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              {/* Body */}
              <p className="text-sm text-muted-foreground leading-relaxed">
                لاسترداد كلمة المرور، يرجى التواصل مع فريق الدعم عبر إحدى القنوات التالية مع ذكر بريدك الإلكتروني المسجّل:
              </p>

              <div className="space-y-3">
                {/* Telegram */}
                <a
                  href="https://t.me/fmf0038"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-3 p-3 rounded-xl bg-[#229ED9]/10 border border-[#229ED9]/20 hover:bg-[#229ED9]/20 transition-colors group"
                >
                  <div className="bg-[#229ED9] p-2 rounded-lg">
                    <MessageCircle className="h-4 w-4 text-white" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground">Telegram</p>
                    <p className="text-xs text-muted-foreground font-mono">@fmf0038</p>
                  </div>
                  <span className="text-xs text-[#229ED9] opacity-0 group-hover:opacity-100 transition-opacity">فتح ←</span>
                </a>

                {/* Email */}
                <a
                  href="mailto:fmf0038@gmail.com?subject=استرداد كلمة المرور - HAYO AI"
                  className="flex items-center gap-3 p-3 rounded-xl bg-muted/50 border border-border hover:bg-muted transition-colors group"
                >
                  <div className="bg-primary/10 p-2 rounded-lg">
                    <Mail className="h-4 w-4 text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground">البريد الإلكتروني</p>
                    <p className="text-xs text-muted-foreground font-mono truncate">fmf0038@gmail.com</p>
                  </div>
                  <span className="text-xs text-primary opacity-0 group-hover:opacity-100 transition-opacity">إرسال ←</span>
                </a>
              </div>

              <Button
                variant="outline"
                className="w-full text-sm"
                onClick={() => setShowForgot(false)}
              >
                حسناً، فهمت
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
