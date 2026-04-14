/**
 * HAYO AI — App Builder (APK Generator) — Enhanced v5
 * الوكيل الذكي يكتب كود React Native ثم يبنيه APK عبر HAYO APK Factory
 */
import { useState, useEffect, useRef, useCallback } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { toast } from "sonner";
import MonacoEditor from "@monaco-editor/react";
import {
  Smartphone, Sparkles, Loader2, Download, ExternalLink, CheckCircle2,
  AlertCircle, Clock, ChevronRight, Code2, Zap, Play, History,
  RefreshCw, Home, Eye, Package, Brain, Cpu, RotateCcw, X, ImageIcon,
  Upload, Rocket, Trash2, ChevronDown, ChevronUp, Search, Filter,
  TrendingUp, BarChart3, Award,
} from "lucide-react";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import { useTranslation } from "react-i18next";

const BASE = import.meta.env.BASE_URL || "/";

// ─── Types ─────────────────────────────────────────────────────
type Step = "describe" | "generating" | "review" | "building" | "done" | "error";
type AIModel = "claude" | "deepseek";
type BuildMode = "create" | "advanced" | "upload" | "desktop" | "desktop-upload";

interface BuildRecord {
  id: number;
  appName: string;
  status: string;
  downloadUrl?: string | null;
  buildLogsUrl?: string | null;
  errorMessage?: string | null;
  createdAt: string;
  updatedAt?: string;
  platform?: string;
}

interface ExtractedFile {
  name: string;
  content: string;
}

interface GenerateCodeResponse {
  code: string;
}

interface BuildCreateResponse {
  buildId: number;
}

interface BuildSyncResponse {
  id: number;
  appName: string;
  status: string;
  downloadUrl?: string | null;
  buildLogsUrl?: string | null;
  errorMessage?: string | null;
  platform?: string;
}

interface BuildDeleteResponse {
  success: boolean;
}

interface StoredBuildInput {
  appName: string;
  description: string;
  generatedCode: string;
  iconUrl?: string;
}

// ─── Status helpers ────────────────────────────────────────────
function statusLabel(status: string) {
  const map: Record<string, { label: string; color: string; icon: React.ComponentType<{ className?: string }> }> = {
    pending:    { label: "في الانتظار",   color: "text-yellow-400",  icon: Clock },
    submitting: { label: "جاري الإرسال",  color: "text-blue-400",   icon: Loader2 },
    building:   { label: "جاري البناء",   color: "text-indigo-400", icon: Cpu },
    in_progress:{ label: "جاري البناء",   color: "text-indigo-400", icon: Cpu },
    queued:     { label: "في الانتظار",   color: "text-yellow-400",  icon: Clock },
    finished:   { label: "اكتمل ✅",       color: "text-emerald-400", icon: CheckCircle2 },
    errored:    { label: "فشل البناء",    color: "text-red-400",    icon: AlertCircle },
    cancelled:  { label: "ملغي",          color: "text-muted-foreground", icon: X },
  };
  return map[status] || { label: status, color: "text-muted-foreground", icon: Clock };
}

// ─── AI Model options ───────────────────────────────────────────
const AI_MODELS: { id: AIModel; name: string; icon: string; badge?: string }[] = [
  { id: "claude",   name: "Claude Opus (Anthropic)", icon: "🧠", badge: "الأقوى" },
  { id: "deepseek", name: "DeepSeek Coder",           icon: "⚡", badge: "سريع" },
];

// ─── Example apps ───────────────────────────────────────────────
const EXAMPLES = [
  { name: "آلة حاسبة", desc: "آلة حاسبة جميلة بعمليات أساسية وعلمية" },
  { name: "قائمة مهام", desc: "تطبيق مهام بإمكانية الإضافة والحذف والتحديد مع حفظ محلي" },
  { name: "ساعة توقف", desc: "ساعة توقف مع إشارات مرجعية وعداد تنازلي" },
  { name: "مفكرة", desc: "تطبيق ملاحظات بحفظ محلي وبحث سريع وتصنيفات" },
  { name: "تطبيق طقس", desc: "تطبيق يجلب بيانات الطقس من الإنترنت حسب الموقع GPS مع توقعات 5 أيام" },
  { name: "تطبيق أخبار", desc: "تطبيق يجلب آخر الأخبار من API خارجي مع تصنيفات ومشاركة" },
  { name: "ماسح QR", desc: "تطبيق ماسح QR Code باستخدام الكاميرا مع حفظ السجل" },
  { name: "مدير كلمات المرور", desc: "تطبيق آمن لحفظ كلمات المرور مشفرة محلياً مع توليد تلقائي" },
  { name: "تتبع المصروفات", desc: "تطبيق تتبع المصروفات والدخل مع رسوم بيانية وتصنيفات" },
  { name: "دليل الأرقام", desc: "تطبيق مثل Truecaller — بحث عن أرقام من قاعدة بيانات مدمجة مع إظهار هوية المتصل" },
];

const MAX_POLL_RETRIES = 30; // 5 min max (30 × 10s)

// ─── Main Component ─────────────────────────────────────────────
export default function AppBuilder() {
  const { t } = useTranslation();
  const { isAuthenticated, loading: authLoading } = useAuth();

  const [step, setStep]           = useState<Step>("describe");
  const [appName, setAppName]     = useState("");
  const [description, setDescription] = useState("");
  const [iconUrl, setIconUrl]     = useState("");
  const [iconPreview, setIconPreview] = useState("");
  const [iconError, setIconError] = useState("");
  const [selectedModel, setSelectedModel] = useState<AIModel>("claude");
  const [generatedCode, setGeneratedCode] = useState("");
  const [currentBuildId, setCurrentBuildId] = useState<number | null>(null);
  const [buildData, setBuildData] = useState<BuildSyncResponse | null>(null);
  const [showCode, setShowCode]   = useState(false);
  const [lastBuildInput, setLastBuildInput] = useState<StoredBuildInput | null>(null);

  // Polling refs
  const pollRef      = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollCount    = useRef(0);

  // Build progress timer
  const [buildElapsed, setBuildElapsed] = useState(0);
  const buildTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const buildStartedAt = useRef<number>(0);

  // Build mode
  const [buildMode, setBuildMode] = useState<BuildMode>("create");

  // Upload project state
  const [uploadFiles, setUploadFiles]   = useState<ExtractedFile[]>([]);
  const [uploadName, setUploadName]     = useState("");
  const [isExtracting, setIsExtracting] = useState(false);
  const [isDragOverUpload, setIsDragOverUpload] = useState(false);
  const uploadRef = useRef<HTMLInputElement>(null);

  // Desktop state
  const [desktopCode, setDesktopCode]               = useState("");
  const [desktopIconBase64, setDesktopIconBase64]   = useState("");
  const [desktopIconPreview, setDesktopIconPreview] = useState("");
  const [isDragOverDesktop, setIsDragOverDesktop]   = useState(false);
  const desktopIconRef = useRef<HTMLInputElement>(null);

  // Desktop upload state
  const [desktopUploadZip, setDesktopUploadZip]           = useState("");
  const [desktopUploadFileName, setDesktopUploadFileName] = useState("");
  const [desktopUploadName, setDesktopUploadName]         = useState("");
  const [isDesktopExtracting, setIsDesktopExtracting]     = useState(false);
  const desktopUploadRef = useRef<HTMLInputElement>(null);

  // Advanced mode state
  const [dataFiles, setDataFiles]               = useState<Array<{ filename: string; content: string; preview: string }>>([]);
  const [apiEndpoints, setApiEndpoints]         = useState<string[]>([]);
  const [newApiUrl, setNewApiUrl]               = useState("");
  const [supabaseUrl, setSupabaseUrl]           = useState("");
  const [supabaseKey, setSupabaseKey]           = useState("");
  const [selectedFeatures, setSelectedFeatures] = useState<string[]>([]);
  const [keystoreBase64, setKeystoreBase64]     = useState("");
  const dataFileRef  = useRef<HTMLInputElement>(null);
  const keystoreRef  = useRef<HTMLInputElement>(null);

  // History state
  const [historySearch, setHistorySearch]       = useState("");
  const [historyFilter, setHistoryFilter]       = useState<"all" | "finished" | "errored" | "building">("all");
  const [historyCollapsed, setHistoryCollapsed] = useState(false);

  const utils = trpc.useUtils();

  // Queries & Mutations
  const { data: builds, refetch: refetchBuilds } = trpc.builds.list.useQuery(
    undefined, { enabled: isAuthenticated }
  );

  const deleteBuildMut = trpc.builds.delete.useMutation({
    onSuccess: () => { refetchBuilds(); toast.success("تم حذف البناء"); },
    onError: (err: Error) => { console.error("[AppBuilder] delete build failed:", err); toast.error("فشل الحذف"); },
  });

  const generateMutation = trpc.builds.generateCode.useMutation({
    onSuccess: (data: GenerateCodeResponse) => {
      setGeneratedCode(data.code);
      setStep("review");
    },
    onError: (err: Error) => {
      console.error("[AppBuilder] generateCode failed:", err);
      toast.error(`فشل توليد الكود: ${err.message}`);
      setStep("describe");
    },
  });

  const desktopGenMut = trpc.builds.generateDesktopCode.useMutation({
    onSuccess: (data: GenerateCodeResponse) => {
      setDesktopCode(data.code);
      setStep("review");
      toast.success("✅ تم توليد كود تطبيق Desktop");
    },
    onError: (err: Error) => {
      console.error("[AppBuilder] generateDesktopCode failed:", err);
      toast.error(`فشل توليد كود Desktop: ${err.message}`);
      setStep("describe");
    },
  });

  const desktopZipMut = trpc.builds.generateDesktopZip.useMutation({
    onSuccess: (data: { zipBase64: string; filename: string }) => {
      try {
        const bin   = atob(data.zipBase64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        const blob = new Blob([bytes], { type: "application/zip" });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a"); a.href = url; a.download = data.filename; a.click();
        URL.revokeObjectURL(url);
        toast.success("✅ تم تحميل مشروع Electron كامل");
        setStep("done");
      } catch (e) {
        console.error("[AppBuilder] desktopZipMut decode failed:", e);
        toast.error("فشل فك تشفير الملف");
      }
    },
    onError: (err: Error) => { console.error("[AppBuilder] desktopZip failed:", err); toast.error(`فشل إنشاء ZIP: ${err.message}`); },
  });

  const createDesktopMut = trpc.builds.createDesktop.useMutation({
    onSuccess: (data: BuildCreateResponse) => {
      setCurrentBuildId(data.buildId);
      setStep("building");
      startPolling(data.buildId);
      toast.success("🖥️ بدأ بناء تطبيق Windows — قد يستغرق 3-8 دقائق");
    },
    onError: (err: Error) => { console.error("[AppBuilder] createDesktop failed:", err); toast.error(`فشل بدء البناء: ${err.message}`); },
  });

  const packageDesktopMut = trpc.builds.packageDesktopZip.useMutation({
    onSuccess: (data: { zipBase64: string; filename: string }) => {
      try {
        const bin   = atob(data.zipBase64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        const blob = new Blob([bytes], { type: "application/zip" });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a"); a.href = url; a.download = data.filename; a.click();
        URL.revokeObjectURL(url);
        toast.success("✅ تم تحميل مشروع Electron معبّأ");
      } catch (e) {
        console.error("[AppBuilder] packageDesktopMut decode failed:", e);
        toast.error("فشل فك تشفير الملف");
      }
    },
    onError: (err: Error) => { console.error("[AppBuilder] packageDesktop failed:", err); toast.error(`فشل تعبئة المشروع: ${err.message}`); },
  });

  const advancedGenMut = trpc.builds.generateAdvancedCode.useMutation({
    onSuccess: (data: GenerateCodeResponse) => {
      setGeneratedCode(data.code);
      setStep("review");
      toast.success("✅ تم توليد كود التطبيق المتقدم");
    },
    onError: (err: Error) => {
      console.error("[AppBuilder] generateAdvancedCode failed:", err);
      toast.error(`فشل: ${err.message}`);
      setStep("describe");
    },
  });

  const uploadBuildMut = trpc.builds.createFromUpload.useMutation({
    onSuccess: (data: BuildCreateResponse) => {
      setCurrentBuildId(data.buildId);
      setStep("building");
      refetchBuilds();
      startPolling(data.buildId);
      toast.success("🚀 بدأ بناء المشروع المرفوع");
    },
    onError: (err: Error) => {
      console.error("[AppBuilder] createFromUpload failed:", err);
      toast.error(`فشل: ${err.message}`);
      setStep("describe");
    },
  });

  const reviewMut = trpc.builds.reviewCode.useMutation({
    onSuccess: (data: { fixedCode: string; issues?: string[] }) => {
      if (buildMode === "desktop") {
        setDesktopCode(data.fixedCode);
      } else {
        setGeneratedCode(data.fixedCode);
      }
      if (data.issues && data.issues.length > 0) {
        toast.success(`🔧 AI أصلح ${data.issues.length} مشكلة`);
      } else {
        toast.success("✅ الكود سليم");
      }
    },
    onError: (err: Error) => { console.error("[AppBuilder] reviewCode failed:", err); toast.error(`فشل الفحص: ${err.message}`); },
  });

  const createMutation = trpc.builds.create.useMutation({
    onSuccess: (data: BuildCreateResponse) => {
      setCurrentBuildId(data.buildId);
      setStep("building");
      refetchBuilds();
      startPolling(data.buildId);
    },
    onError: (err: Error) => {
      console.error("[AppBuilder] create build failed:", err);
      let msg = err.message || "خطأ غير معروف";
      if (msg.includes("max") || msg.includes("too_big")) {
        msg = "الوصف طويل جداً — الحد الأقصى 1000 حرف";
      } else if (msg.includes("url") || msg.includes("Invalid url")) {
        msg = "رابط الأيقونة غير صحيح — يجب أن يبدأ بـ https://";
      } else if (msg.includes("min") || msg.includes("too_small")) {
        msg = "أحد الحقول قصير جداً — تأكد من ملء جميع البيانات";
      }
      toast.error(`فشل بدء البناء: ${msg}`, { duration: 6000 });
      setStep("review");
    },
  });

  const syncMutation = trpc.builds.sync.useMutation({
    onSuccess: (data: BuildSyncResponse) => {
      setBuildData(data);
      if (data?.status === "finished") {
        setStep("done");
        stopPolling();
        stopBuildTimer();
        refetchBuilds();
        toast.success("🎉 تم بناء التطبيق بنجاح! يمكنك تحميله الآن.");
      } else if (data?.status === "errored") {
        setStep("error");
        stopPolling();
        stopBuildTimer();
        refetchBuilds();
        toast.error("فشل بناء التطبيق");
      }
    },
    onError: (err: Error) => {
      console.error("[AppBuilder] sync failed:", err);
    },
  });

  // ─── Polling with debounce guard and max retries ─────────────
  function startPolling(buildId: number) {
    if (pollRef.current) return; // debounce: already polling
    pollCount.current = 0;
    buildStartedAt.current = Date.now();
    startBuildTimer();

    pollRef.current = setInterval(() => {
      pollCount.current += 1;
      if (pollCount.current > MAX_POLL_RETRIES) {
        stopPolling();
        stopBuildTimer();
        toast.error("انتهت مهلة التحقق (5 دقائق) — حاول التحديث يدوياً");
        return;
      }
      syncMutation.mutate({ buildId });
    }, 10_000);
  }

  function stopPolling() {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    pollCount.current = 0;
  }

  function startBuildTimer() {
    stopBuildTimer();
    setBuildElapsed(0);
    buildTimerRef.current = setInterval(() => {
      setBuildElapsed(Math.floor((Date.now() - buildStartedAt.current) / 1000));
    }, 1000);
  }

  function stopBuildTimer() {
    if (buildTimerRef.current) {
      clearInterval(buildTimerRef.current);
      buildTimerRef.current = null;
    }
  }

  useEffect(() => () => { stopPolling(); stopBuildTimer(); }, []);

  // Resume polling if we reload with an active build
  useEffect(() => {
    if (currentBuildId && step === "building") {
      startPolling(currentBuildId);
    }
  }, []);

  // ─── Handlers ────────────────────────────────────────────────
  const handleGenerate = () => {
    if (generateMutation.isPending) return;
    if (!appName.trim()) { toast.error("أدخل اسم التطبيق"); return; }
    if (!description.trim() || description.length < 10) { toast.error("الوصف قصير جداً (10 أحرف على الأقل)"); return; }
    if (description.length > 3000) { toast.error("الوصف طويل جداً — الحد الأقصى 3000 حرف"); return; }
    setStep("generating");
    generateMutation.mutate({ appName: appName.trim(), description: description.trim(), model: selectedModel });
  };

  const handleBuild = () => {
    if (!generatedCode) return;
    if (createMutation.isPending) return;
    const cleanIconUrl = iconUrl.trim();
    if (cleanIconUrl) {
      try {
        const parsed = new URL(cleanIconUrl);
        if (!["http:", "https:"].includes(parsed.protocol)) {
          toast.error("رابط الأيقونة يجب أن يبدأ بـ https://");
          return;
        }
      } catch {
        toast.error("رابط الأيقونة غير صحيح — تأكد أنه يبدأ بـ https://");
        return;
      }
    }
    const input: StoredBuildInput = {
      appName: appName.trim(),
      description: description.trim().slice(0, 3000),
      generatedCode,
      iconUrl: cleanIconUrl || undefined,
    };
    setLastBuildInput(input);
    createMutation.mutate(input);
  };

  const handleRetryBuild = () => {
    if (createMutation.isPending) return;
    const input = lastBuildInput;
    if (!input) { setStep("describe"); return; }
    // Use updated generatedCode if AI fixed it
    const codeToUse = generatedCode || input.generatedCode;
    stopPolling();
    stopBuildTimer();
    setBuildData(null);
    const finalInput = { ...input, generatedCode: codeToUse };
    setLastBuildInput(finalInput);
    setStep("building");
    createMutation.mutate(finalInput);
  };

  const handleReset = () => {
    stopPolling();
    stopBuildTimer();
    setStep("describe");
    setGeneratedCode("");
    setDesktopCode("");
    setCurrentBuildId(null);
    setBuildData(null);
    setShowCode(false);
    setIconUrl("");
    setIconPreview("");
    setIconError("");
    setUploadFiles([]);
    setUploadName("");
    setDataFiles([]);
    setApiEndpoints([]);
    setNewApiUrl("");
    setSupabaseUrl("");
    setSupabaseKey("");
    setSelectedFeatures([]);
    setKeystoreBase64("");
    setDesktopIconBase64("");
    setDesktopIconPreview("");
    setDesktopUploadZip("");
    setDesktopUploadFileName("");
    setDesktopUploadName("");
    setLastBuildInput(null);
    setBuildElapsed(0);
  };

  const handleDesktopIcon = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const dataUrl = e.target?.result as string;
      setDesktopIconBase64(dataUrl);
      setDesktopIconPreview(dataUrl);
      toast.success(`🎨 تم تحميل الأيقونة: ${file.name}`);
    };
    reader.onerror = () => { console.error("[AppBuilder] failed to read desktop icon"); toast.error("فشل قراءة الأيقونة"); };
    reader.readAsDataURL(file);
  };

  const handleDesktopUploadFile = (file: File) => {
    setIsDesktopExtracting(true);
    setDesktopUploadFileName(file.name);
    if (!desktopUploadName) setDesktopUploadName(file.name.replace(/\.(zip|rar)$/i, ""));
    const reader = new FileReader();
    reader.onload = (e) => {
      const arrayBuf = e.target?.result as ArrayBuffer;
      const bytes    = new Uint8Array(arrayBuf);
      let binary     = "";
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      setDesktopUploadZip(btoa(binary));
      setIsDesktopExtracting(false);
      toast.success(`📦 تم تحميل: ${file.name}`);
    };
    reader.onerror = () => { console.error("[AppBuilder] failed to read desktop ZIP"); setIsDesktopExtracting(false); toast.error("فشل قراءة الملف"); };
    reader.readAsArrayBuffer(file);
  };

  const handleDataFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      const preview = content.substring(0, 300);
      setDataFiles(prev => [...prev, { filename: file.name, content, preview }]);
      toast.success(`📊 ${file.name} — ${(content.length / 1024).toFixed(1)}KB`);
    };
    reader.onerror = () => { console.error("[AppBuilder] failed to read data file"); toast.error("فشل قراءة ملف البيانات"); };
    reader.readAsText(file);
  };

  const handleKeystoreUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const arrayBuf = e.target?.result as ArrayBuffer;
      const base64   = btoa(String.fromCharCode(...new Uint8Array(arrayBuf)));
      setKeystoreBase64(base64);
      toast.success("🔑 تم تحميل ملف التوقيع");
    };
    reader.onerror = () => { console.error("[AppBuilder] failed to read keystore"); toast.error("فشل قراءة ملف التوقيع"); };
    reader.readAsArrayBuffer(file);
  };

  const toggleFeature = (f: string) => {
    setSelectedFeatures(prev => prev.includes(f) ? prev.filter(x => x !== f) : [...prev, f]);
  };

  const handleAdvancedBuild = () => {
    if (advancedGenMut.isPending || createMutation.isPending) return;
    if (!appName.trim()) { toast.error("أدخل اسم التطبيق"); return; }
    if (!description.trim() || description.length < 10) { toast.error("الوصف قصير"); return; }
    setStep("generating");
    advancedGenMut.mutate(
      {
        appName: appName.trim(),
        description: description.trim(),
        model: selectedModel,
        dataFiles: dataFiles.map(d => ({ filename: d.filename, preview: d.preview })),
        apiEndpoints: apiEndpoints.length > 0 ? apiEndpoints : undefined,
        useSupabase: !!supabaseUrl,
        features: selectedFeatures.length > 0 ? selectedFeatures : undefined,
      },
      {
        onSuccess: (data: GenerateCodeResponse) => {
          setGeneratedCode(data.code);
          toast.success("✅ تم التوليد — بدء البناء التلقائي...");
          const buildInput: StoredBuildInput = {
            appName: appName.trim(),
            description: description.trim().slice(0, 3000),
            generatedCode: data.code,
            iconUrl: iconUrl.trim() || undefined,
          };
          setLastBuildInput(buildInput);
          createMutation.mutate({
            ...buildInput,
            embeddedData: dataFiles.map(d => ({ filename: d.filename, content: d.content })),
            supabaseUrl: supabaseUrl || undefined,
            supabaseKey: supabaseKey || undefined,
            customKeystoreBase64: keystoreBase64 || undefined,
          });
        },
      }
    );
  };

  // Handle ZIP upload with AbortController (60s timeout) + drag-and-drop
  const handleUploadFile = useCallback(async (file: File) => {
    if (!file) return;
    setIsExtracting(true);
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 60_000);
    try {
      const fd  = new FormData();
      fd.append("file", file);
      const res  = await fetch("/api/files/extract-archive", {
        method: "POST", body: fd, credentials: "include",
        signal: controller.signal,
      });
      const data = await res.json() as { files?: ExtractedFile[]; error?: string };
      if (!res.ok) { toast.error(data.error || "فشل الاستخراج"); return; }
      const files = data.files ?? [];
      setUploadFiles(files);
      if (!uploadName) {
        const pkgFile = files.find((f: ExtractedFile) => f.name === "package.json");
        if (pkgFile) {
          try {
            const parsed = JSON.parse(pkgFile.content) as { name?: string };
            setUploadName(parsed.name || file.name.replace(/\.\w+$/, ""));
          } catch {
            setUploadName(file.name.replace(/\.\w+$/, ""));
          }
        } else {
          setUploadName(file.name.replace(/\.\w+$/, ""));
        }
      }
      toast.success(`✅ ${files.length} ملف مستخرج`);
    } catch (e: unknown) {
      const err = e as Error;
      if (err.name === "AbortError") {
        console.error("[AppBuilder] file upload timed out after 60s");
        toast.error("انتهت مهلة الرفع (60 ثانية) — حاول مع ملف أصغر");
      } else {
        console.error("[AppBuilder] file upload error:", err);
        toast.error(err.message || "خطأ غير معروف");
      }
    } finally {
      clearTimeout(timeoutId);
      setIsExtracting(false);
    }
  }, [uploadName]);

  const handleUploadBuild = () => {
    if (!uploadFiles.length) { toast.error("ارفع ملفات المشروع أولاً"); return; }
    if (!uploadName.trim()) { toast.error("أدخل اسم التطبيق"); return; }
    if (uploadBuildMut.isPending) return;
    setStep("building");
    uploadBuildMut.mutate({
      appName: uploadName.trim(),
      files: uploadFiles,
      iconUrl: iconUrl.trim() || undefined,
    });
  };

  // ─── Build Stats ────────────────────────────────────────────
  const buildsList = (builds as BuildRecord[] | undefined) ?? [];
  const totalBuilds    = buildsList.length;
  const successBuilds  = buildsList.filter(b => b.status === "finished").length;
  const failedBuilds   = buildsList.filter(b => b.status === "errored").length;

  // ─── History filtering ───────────────────────────────────────
  const filteredBuilds = buildsList
    .filter(b => historyFilter === "all" || b.status === historyFilter)
    .filter(b => !historySearch || b.appName.toLowerCase().includes(historySearch.toLowerCase()));

  // Progress bar calculation (estimated 10 min build)
  const ESTIMATED_SECS = 600;
  const progressPct    = Math.min(99, Math.round((buildElapsed / ESTIMATED_SECS) * 100));

  // ─── Guard ───────────────────────────────────────────────────
  if (authLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <div className="text-center space-y-4 max-w-sm">
          <Smartphone className="w-16 h-16 text-primary/40 mx-auto" />
          <h2 className="text-xl font-bold">{t("appBuilder.loginRequired")}</h2>
          <p className="text-muted-foreground text-sm">{t("appBuilder.loginDesc")}</p>
          <Link href={getLoginUrl()}>
            <Button className="w-full">{t("common.login")}</Button>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">

      {/* ─── Header (glassmorphism + gradient) ──────────────── */}
      <header className="sticky top-0 z-30 border-b border-white/5">
        <div className="absolute inset-0 bg-gradient-to-l from-emerald-900/30 via-slate-900/80 to-indigo-900/30 backdrop-blur-md" />
        <div className="relative max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/">
              <button className="p-1.5 rounded-lg hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors">
                <Home className="w-4 h-4" />
              </button>
            </Link>
            <div className="flex items-center gap-2">
              <img src={`${BASE}logo.png`} alt="HAYO" className="w-7 h-7 rounded-lg"
                onError={e => { (e.target as HTMLImageElement).style.display = "none"; }} />
              <span className="font-heading font-bold text-sm bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
                {t("appBuilder.title")}
              </span>
            </div>
            <span className="hidden sm:flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 font-medium border border-emerald-500/30">
              <Zap className="w-3 h-3" /> HAYO APK Factory
            </span>
          </div>
          <LanguageSwitcher />
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-4 py-8 space-y-8">

        {/* Hero */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-xs font-medium text-primary">
            <Smartphone className="w-3.5 h-3.5" />
            {t("appBuilder.tagline")}
          </div>
          <h1 className="text-3xl sm:text-4xl font-heading font-black">
            {t("appBuilder.heroTitle")}
          </h1>
          <p className="text-muted-foreground max-w-lg mx-auto text-sm leading-relaxed">
            {t("appBuilder.heroDesc")}
          </p>
        </div>

        {/* ─── Build Stats Cards ───────────────────────────────── */}
        {totalBuilds > 0 && step === "describe" && (
          <div className="grid grid-cols-3 gap-3">
            {[
              { icon: BarChart3,    label: "إجمالي البناءات",   value: totalBuilds,   color: "from-blue-600/20 to-blue-800/10",    border: "border-blue-500/20",  text: "text-blue-400" },
              { icon: Award,        label: "بناءات ناجحة",     value: successBuilds,  color: "from-emerald-600/20 to-emerald-800/10", border: "border-emerald-500/20", text: "text-emerald-400" },
              { icon: TrendingUp,   label: "تطبيقات فعلية",   value: successBuilds,  color: "from-violet-600/20 to-violet-800/10", border: "border-violet-500/20", text: "text-violet-400" },
            ].map((stat, i) => (
              <div key={i} className={`relative overflow-hidden rounded-xl bg-gradient-to-br ${stat.color} border ${stat.border} p-3 sm:p-4 text-center`}>
                <stat.icon className={`w-5 h-5 mx-auto mb-1 ${stat.text}`} />
                <div className={`text-2xl font-bold ${stat.text}`}>{stat.value}</div>
                <div className="text-[10px] text-muted-foreground">{stat.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Build Mode Tabs */}
        {step === "describe" && (
          <div className="flex gap-2 justify-center flex-wrap">
            {([
              { id: "create" as BuildMode,         label: "إنشاء تطبيق",    icon: "✨", desc: "AI يكتب الكود" },
              { id: "advanced" as BuildMode,        label: "تطبيق متقدم",    icon: "🚀", desc: "بيانات + APIs" },
              { id: "upload" as BuildMode,          label: "رفع مشروع",      icon: "📤", desc: "رفع ZIP جاهز" },
              { id: "desktop" as BuildMode,         label: "Desktop بالذكاء",icon: "🖥️", desc: "AI يكتب Electron" },
              { id: "desktop-upload" as BuildMode,  label: "رفع Desktop",    icon: "📦", desc: "ZIP → Electron" },
            ]).map(m => (
              <button key={m.id} onClick={() => setBuildMode(m.id)}
                className={`flex flex-col items-center gap-1 px-5 py-3 rounded-xl border text-sm font-medium transition-all ${
                  buildMode === m.id ? "bg-primary/15 border-primary text-primary" : "bg-card border-border text-muted-foreground hover:text-foreground hover:border-primary/30"
                }`}>
                <span className="text-xl">{m.icon}</span>
                <span>{m.label}</span>
                <span className="text-[10px] opacity-60">{m.desc}</span>
              </button>
            ))}
          </div>
        )}

        {/* Steps indicator */}
        <div className="flex items-center justify-center gap-2 text-xs">
          {[
            { key: "describe",   label: t("appBuilder.stepDescribe") },
            { key: "generating", label: t("appBuilder.stepGenerating") },
            { key: "review",     label: t("appBuilder.stepReview") },
            { key: "building",   label: t("appBuilder.stepBuilding") },
            { key: "done",       label: t("appBuilder.stepDone") },
          ].map((s, i) => {
            const steps      = ["describe", "generating", "review", "building", "done", "error"];
            const currentIdx = steps.indexOf(step);
            const sIdx       = steps.indexOf(s.key);
            const active     = step === s.key || (s.key === "done" && step === "error");
            const done       = currentIdx > sIdx;
            return (
              <div key={s.key} className="flex items-center gap-2">
                {i > 0 && <div className={`w-6 h-px ${done ? "bg-primary" : "bg-border"}`} />}
                <div className={`flex items-center gap-1 px-2 py-1 rounded-full transition-all ${
                  active ? "bg-primary/15 text-primary font-medium" :
                  done   ? "text-primary" : "text-muted-foreground"
                }`}>
                  {done ? <CheckCircle2 className="w-3 h-3" /> : <span className="w-3 h-3 text-center text-[10px]">{i + 1}</span>}
                  <span className="hidden sm:block">{s.label}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* ─── Step: Describe (Create Mode) ───────────────────────── */}
        {step === "describe" && buildMode === "create" && (
          <div className="max-w-2xl mx-auto space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-medium">{t("appBuilder.appName")}</label>
              <input value={appName} onChange={e => setAppName(e.target.value)}
                placeholder={t("appBuilder.appNamePlaceholder")} maxLength={60}
                className="w-full px-4 py-3 bg-card border border-border rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 placeholder:text-muted-foreground/50" />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">{t("appBuilder.appDesc")}</label>
              <textarea value={description} onChange={e => setDescription(e.target.value.slice(0, 3000))}
                rows={6} maxLength={3000}
                placeholder="صِف بالتفصيل ما تريده... مثلاً: تطبيق آلة حاسبة بواجهة حديثة، يحتوي على العمليات الأساسية (جمع، طرح، ضرب، قسمة) والعمليات العلمية، مع تاريخ للعمليات السابقة."
                className="w-full px-4 py-3 bg-card border border-border rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 placeholder:text-muted-foreground/50 resize-none" />
              <p className={`text-xs text-left ${description.length >= 2700 ? "text-yellow-400 font-medium" : "text-muted-foreground"}`}>
                {description.length} / 3000
                {description.length >= 2700 && description.length < 3000 && " — اقترب الحد"}
                {description.length >= 3000 && " — وصلت الحد الأقصى"}
              </p>
            </div>

            {/* App Icon */}
            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <ImageIcon className="w-4 h-4 text-primary" />
                أيقونة التطبيق
                <span className="text-xs text-muted-foreground font-normal">(اختياري)</span>
              </label>
              <div className="flex items-center gap-3">
                <div className="w-16 h-16 rounded-2xl border-2 border-dashed border-border bg-secondary/30 flex items-center justify-center overflow-hidden shrink-0">
                  {iconPreview ? (
                    <img src={iconPreview} alt="أيقونة التطبيق" className="w-full h-full object-cover rounded-2xl"
                      onError={() => { setIconPreview(""); toast.error("تعذّر تحميل الصورة — تأكد من صحة الرابط"); }} />
                  ) : (
                    <Smartphone className="w-7 h-7 text-muted-foreground/40" />
                  )}
                </div>
                <div className="flex-1 space-y-1.5">
                  <input value={iconUrl} onChange={e => { setIconUrl(e.target.value); setIconError(""); }}
                    onBlur={() => {
                      const val = iconUrl.trim();
                      if (!val) { setIconError(""); return; }
                      try {
                        const parsed = new URL(val);
                        if (!["http:", "https:"].includes(parsed.protocol)) {
                          setIconError("يجب أن يبدأ الرابط بـ https://");
                          return;
                        }
                        setIconPreview(val);
                        setIconError("");
                      } catch {
                        setIconError("رابط غير صحيح — مثال: https://example.com/icon.png");
                      }
                    }}
                    placeholder="https://example.com/icon.png (1024×1024 مُفضَّل)"
                    className={`w-full px-3 py-2.5 bg-card border rounded-xl text-sm focus:outline-none focus:ring-2 placeholder:text-muted-foreground/40 font-mono text-xs ${
                      iconError ? "border-red-500 focus:ring-red-500/50" : "border-border focus:ring-primary/50"
                    }`}
                    dir="ltr" />
                  {iconError ? (
                    <p className="text-[10px] text-red-400">{iconError}</p>
                  ) : (
                    <p className="text-[10px] text-muted-foreground">
                      أدخل رابط صورة PNG مربعة (1024×1024) — ستُستخدم كأيقونة التطبيق على الهاتف
                    </p>
                  )}
                </div>
                {iconUrl && (
                  <button onClick={() => { setIconUrl(""); setIconPreview(""); setIconError(""); }}
                    className="p-1.5 rounded-lg hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors shrink-0">
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>

            {/* Examples */}
            <div className="space-y-2">
              <p className="text-xs text-muted-foreground">أمثلة سريعة:</p>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {EXAMPLES.map(ex => (
                  <button key={ex.name} onClick={() => { setAppName(ex.name); setDescription(ex.desc); }}
                    className="text-right px-3 py-2 bg-secondary/50 hover:bg-secondary border border-border/50 rounded-lg text-xs transition-all hover:border-primary/30 hover:text-primary">
                    {ex.name}
                  </button>
                ))}
              </div>
            </div>

            {/* AI Model */}
            <div className="space-y-2">
              <label className="text-sm font-medium">{t("appBuilder.aiModel")}</label>
              <div className="grid grid-cols-2 gap-3">
                {AI_MODELS.map(m => (
                  <button key={m.id} onClick={() => setSelectedModel(m.id)}
                    className={`flex items-center gap-3 px-4 py-3 rounded-xl border text-xs font-medium transition-all ${
                      selectedModel === m.id
                        ? "border-primary bg-primary/10 text-primary"
                        : "border-border bg-card hover:border-primary/30 text-muted-foreground hover:text-foreground"
                    }`}>
                    <span className="text-xl">{m.icon}</span>
                    <div className="text-right">
                      <div className="font-bold">{m.name}</div>
                      {m.badge && (
                        <div className={`text-[9px] mt-0.5 ${selectedModel === m.id ? "text-primary/70" : "text-muted-foreground/60"}`}>
                          {m.badge}
                        </div>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="flex gap-3">
              <Button onClick={handleGenerate} variant="outline" className="flex-1 py-6 text-base gap-2"
                disabled={generateMutation.isPending || createMutation.isPending}>
                <Code2 className="w-5 h-5" />
                توليد ومراجعة
              </Button>
              <Button onClick={() => {
                if (generateMutation.isPending || createMutation.isPending) return;
                if (!appName.trim()) { toast.error("أدخل اسم التطبيق"); return; }
                if (!description.trim() || description.length < 10) { toast.error("الوصف قصير"); return; }
                setStep("generating");
                generateMutation.mutate(
                  { appName: appName.trim(), description: description.trim(), model: selectedModel },
                  {
                    onSuccess: (data: GenerateCodeResponse) => {
                      setGeneratedCode(data.code);
                      toast.success("✅ تم التوليد — بدء البناء التلقائي...");
                      const cleanIcon = iconUrl.trim();
                      const buildIn: StoredBuildInput = {
                        appName: appName.trim(),
                        description: description.trim().slice(0, 3000),
                        generatedCode: data.code,
                        iconUrl: cleanIcon || undefined,
                      };
                      setLastBuildInput(buildIn);
                      createMutation.mutate(buildIn);
                    },
                  }
                );
              }} className="flex-1 py-6 text-base gap-2 bg-emerald-600 hover:bg-emerald-700"
                disabled={generateMutation.isPending || createMutation.isPending}>
                <Rocket className="w-5 h-5" />
                🚀 بناء تلقائي كامل
              </Button>
            </div>
          </div>
        )}

        {/* ─── Mode: Advanced App ────────────────────────────── */}
        {step === "describe" && buildMode === "advanced" && (
          <div className="max-w-2xl mx-auto space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">اسم التطبيق</label>
                <input value={appName} onChange={e => setAppName(e.target.value)} placeholder="مثال: دليل الأرقام..." className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">نموذج AI</label>
                <div className="flex gap-2">
                  {AI_MODELS.map(m => (
                    <button key={m.id} onClick={() => setSelectedModel(m.id)} className={`flex-1 flex items-center gap-2 p-2.5 rounded-xl border text-xs ${selectedModel === m.id ? "border-primary bg-primary/10" : "border-border bg-card"}`}>
                      <span>{m.icon}</span><span className="font-medium">{m.name.split(" ")[0]}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">وصف التطبيق التفصيلي</label>
              <textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="صف بالتفصيل: ماذا يفعل التطبيق، ما الشاشات، ما الميزات، كيف يتفاعل مع البيانات..." rows={4} className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none" />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">الميزات المطلوبة</label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {[
                  { id: "camera",      label: "الكاميرا",     icon: "📷" },
                  { id: "location",    label: "الموقع GPS",   icon: "📍" },
                  { id: "notifications", label: "إشعارات",    icon: "🔔" },
                  { id: "imagePicker", label: "اختيار صور",  icon: "🖼️" },
                  { id: "fileSystem",  label: "نظام ملفات",  icon: "📁" },
                  { id: "sharing",     label: "مشاركة",       icon: "📤" },
                  { id: "sensors",     label: "مستشعرات",     icon: "📡" },
                  { id: "webBrowser",  label: "متصفح ويب",   icon: "🌐" },
                ].map(f => (
                  <button key={f.id} onClick={() => toggleFeature(f.id)} className={`flex items-center gap-2 p-2 rounded-lg border text-xs transition-all ${selectedFeatures.includes(f.id) ? "bg-primary/15 border-primary text-primary" : "bg-card border-border text-muted-foreground hover:border-primary/30"}`}>
                    <span>{f.icon}</span><span>{f.label}</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">📊 بيانات مدمجة <span className="text-xs text-muted-foreground">(CSV / JSON)</span></label>
              <div className="border border-dashed border-border rounded-xl p-4 space-y-3">
                <button onClick={() => dataFileRef.current?.click()} className="w-full flex items-center justify-center gap-2 text-sm text-muted-foreground hover:text-foreground py-2">
                  <Upload className="w-4 h-4" /> رفع ملفات بيانات
                </button>
                <input ref={dataFileRef} type="file" accept=".csv,.json,.txt,.tsv" multiple className="hidden"
                  onChange={e => { if (e.target.files) Array.from(e.target.files).forEach(handleDataFile); }} />
                {dataFiles.length > 0 && (
                  <div className="space-y-1.5">{dataFiles.map((d, i) => (
                    <div key={i} className="flex items-center gap-2 bg-muted/30 rounded-lg p-2 text-xs">
                      <span>📄</span><span className="font-mono flex-1 truncate">{d.filename}</span>
                      <span className="text-muted-foreground">{(d.content.length / 1024).toFixed(1)}KB</span>
                      <button onClick={() => setDataFiles(prev => prev.filter((_, j) => j !== i))} className="text-red-400"><X className="w-3 h-3" /></button>
                    </div>
                  ))}</div>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">🔗 APIs خارجية <span className="text-xs text-muted-foreground">(اختياري)</span></label>
              <div className="flex gap-2">
                <input value={newApiUrl} onChange={e => setNewApiUrl(e.target.value)} placeholder="https://api.example.com/data" className="flex-1 bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm font-mono text-left" dir="ltr" />
                <Button size="sm" onClick={() => {
                  if (newApiUrl.startsWith("http")) { setApiEndpoints(prev => [...prev, newApiUrl]); setNewApiUrl(""); }
                  else { toast.error("رابط غير صحيح"); }
                }}>إضافة</Button>
              </div>
              {apiEndpoints.length > 0 && (
                <div className="space-y-1">{apiEndpoints.map((url, i) => (
                  <div key={i} className="flex items-center gap-2 bg-muted/30 rounded-lg p-2 text-xs font-mono" dir="ltr">
                    <span className="text-emerald-400">🔗</span><span className="flex-1 truncate">{url}</span>
                    <button onClick={() => setApiEndpoints(prev => prev.filter((_, j) => j !== i))} className="text-red-400"><X className="w-3 h-3" /></button>
                  </div>
                ))}</div>
              )}
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">🗄️ Supabase <span className="text-xs text-muted-foreground">(اختياري)</span></label>
              <div className="grid grid-cols-2 gap-2">
                <input value={supabaseUrl} onChange={e => setSupabaseUrl(e.target.value)} placeholder="https://xxx.supabase.co" className="bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs font-mono" dir="ltr" />
                <input value={supabaseKey} onChange={e => setSupabaseKey(e.target.value)} placeholder="anon key..." className="bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs font-mono" dir="ltr" type="password" />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">🔑 توقيع مخصص <span className="text-xs text-muted-foreground">(اختياري)</span></label>
              <div className="flex gap-2 items-center">
                <Button variant="outline" size="sm" onClick={() => keystoreRef.current?.click()} className="gap-2 text-xs">
                  <Upload className="w-3 h-3" /> {keystoreBase64 ? "✅ تم التحميل" : "رفع keystore"}
                </Button>
                <input ref={keystoreRef} type="file" accept=".keystore,.jks" className="hidden"
                  onChange={e => { const f = e.target.files?.[0]; if (f) handleKeystoreUpload(f); }} />
                {keystoreBase64 && <button onClick={() => setKeystoreBase64("")} className="text-xs text-red-400">إزالة</button>}
                <span className="text-xs text-muted-foreground mr-auto">التطبيق يُوقّع باسمك</span>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">🎨 أيقونة التطبيق</label>
              <input value={iconUrl} onChange={e => setIconUrl(e.target.value)} placeholder="رابط صورة PNG (اختياري)" className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm" dir="ltr" />
            </div>

            <Button onClick={handleAdvancedBuild} disabled={advancedGenMut.isPending || createMutation.isPending} className="w-full py-6 text-base gap-2 bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500">
              {advancedGenMut.isPending || createMutation.isPending ? <><Loader2 className="w-5 h-5 animate-spin" /> جاري التوليد والبناء...</> : <><Rocket className="w-5 h-5" /> 🚀 بناء تلقائي كامل</>}
            </Button>
          </div>
        )}

        {/* ─── Mode: Upload Project (Mobile) ────────────────── */}
        {step === "describe" && buildMode === "upload" && (
          <div className="max-w-2xl mx-auto space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-medium">اسم التطبيق</label>
              <input value={uploadName} onChange={e => setUploadName(e.target.value)} placeholder="اسم التطبيق..."
                className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" />
            </div>

            {/* Drag-and-drop ZIP zone */}
            <div
              className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all ${
                isDragOverUpload ? "border-primary bg-primary/10 scale-[1.01]" :
                uploadFiles.length > 0 ? "border-emerald-500/40 bg-emerald-500/5" :
                "border-border hover:border-primary/40"
              }`}
              onClick={() => uploadRef.current?.click()}
              onDragOver={e => { e.preventDefault(); setIsDragOverUpload(true); }}
              onDragLeave={() => setIsDragOverUpload(false)}
              onDrop={e => {
                e.preventDefault();
                setIsDragOverUpload(false);
                const file = e.dataTransfer.files[0];
                if (file && /\.(zip|rar)$/i.test(file.name)) { handleUploadFile(file); }
                else { toast.error("نوع الملف غير مدعوم — ZIP أو RAR فقط"); }
              }}
            >
              <input ref={uploadRef} type="file" accept=".zip,.rar" className="hidden"
                onChange={e => { const f = e.target.files?.[0]; if (f) handleUploadFile(f); }} />
              {isExtracting ? (
                <div className="space-y-2">
                  <Loader2 className="w-8 h-8 mx-auto animate-spin text-primary" />
                  <p className="text-sm">جاري استخراج الملفات...</p>
                </div>
              ) : uploadFiles.length > 0 ? (
                <div className="space-y-3">
                  <Package className="w-10 h-10 mx-auto text-emerald-400" />
                  <p className="font-semibold text-emerald-300">{uploadFiles.length} ملف مستخرج</p>
                  <div className="text-xs text-muted-foreground max-h-32 overflow-y-auto space-y-0.5 text-left" dir="ltr">
                    {uploadFiles.slice(0, 15).map((f, i) => <div key={i} className="truncate">📄 {f.name}</div>)}
                    {uploadFiles.length > 15 && <div className="text-primary">+{uploadFiles.length - 15} ملفات أخرى</div>}
                  </div>
                  <button onClick={e => { e.stopPropagation(); setUploadFiles([]); }} className="text-xs text-red-400">
                    <X className="w-3 h-3 inline" /> إعادة اختيار
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  <Upload className="w-8 h-8 mx-auto text-muted-foreground" />
                  <p className="text-sm font-medium">
                    {isDragOverUpload ? "🎯 أسقط الملف هنا!" : "اسحب ملف ZIP/RAR أو انقر للاختيار"}
                  </p>
                  <p className="text-xs text-muted-foreground">حجم مفتوح — يدعم React Native, Expo, أي مشروع</p>
                  <p className="text-[10px] text-muted-foreground/60">مهلة الرفع: 60 ثانية</p>
                </div>
              )}
            </div>

            <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-3 text-xs text-blue-300 space-y-1">
              <p className="font-semibold">🤖 ما يحدث عند الرفع:</p>
              <p>1. AI (Claude Opus) يفحص كل الأكواد ويصلح الأخطاء تلقائياً</p>
              <p>2. يُبنى مشروع Expo متوافق مع SDK 52</p>
              <p>3. يُرسل لـ Expo EAS Cloud لبناء APK</p>
              <p>4. عند الفشل، AI يحلل الخطأ ويعيد المحاولة تلقائياً (3 محاولات)</p>
            </div>

            <Button onClick={handleUploadBuild}
              disabled={uploadFiles.length === 0 || !uploadName.trim() || uploadBuildMut.isPending}
              className="w-full py-6 text-base gap-2 bg-emerald-600 hover:bg-emerald-700">
              {uploadBuildMut.isPending ? <><Loader2 className="w-5 h-5 animate-spin" /> جاري المعالجة...</> : <><Zap className="w-5 h-5" /> فحص وبناء APK</>}
            </Button>
          </div>
        )}

        {/* ─── Mode: Desktop App (AI) ────────────────────────── */}
        {step === "describe" && buildMode === "desktop" && (
          <div className="max-w-2xl mx-auto space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-medium">اسم التطبيق</label>
              <input value={appName} onChange={e => setAppName(e.target.value)} placeholder="اسم التطبيق Desktop..."
                className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">وصف التطبيق</label>
              <textarea value={description} onChange={e => setDescription(e.target.value)}
                placeholder="صف التطبيق بالتفصيل — ماذا يفعل، ما الميزات المطلوبة..." rows={5}
                className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none" />
            </div>

            {/* Desktop Icon Upload */}
            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <ImageIcon className="w-4 h-4 text-primary" />
                لوغو / أيقونة التطبيق
                <span className="text-xs text-muted-foreground font-normal">(اختياري — PNG مُفضَّل)</span>
              </label>
              <div className="flex items-center gap-3">
                <div
                  className="w-16 h-16 rounded-2xl border-2 border-dashed border-border bg-secondary/30 flex items-center justify-center overflow-hidden shrink-0 cursor-pointer hover:border-primary/50 transition-colors"
                  onClick={() => desktopIconRef.current?.click()}
                >
                  {desktopIconPreview ? (
                    <img src={desktopIconPreview} alt="أيقونة" className="w-full h-full object-cover rounded-2xl" />
                  ) : (
                    <Upload className="w-6 h-6 text-muted-foreground/40" />
                  )}
                </div>
                <input ref={desktopIconRef} type="file" accept="image/*" className="hidden"
                  onChange={e => { const f = e.target.files?.[0]; if (f) handleDesktopIcon(f); }} />
                <div className="flex-1 space-y-1">
                  <Button variant="outline" size="sm" onClick={() => desktopIconRef.current?.click()} className="gap-2 text-xs w-full">
                    <Upload className="w-3 h-3" />
                    {desktopIconPreview ? "✅ تم رفع الأيقونة — انقر للتغيير" : "رفع صورة (PNG / JPG / ICO)"}
                  </Button>
                  {desktopIconPreview && (
                    <button onClick={() => { setDesktopIconBase64(""); setDesktopIconPreview(""); }} className="text-xs text-red-400 w-full text-center">إزالة الأيقونة</button>
                  )}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {AI_MODELS.map(m => (
                <button key={m.id} onClick={() => setSelectedModel(m.id)} className={`flex items-center gap-3 p-3 rounded-xl border transition-all ${selectedModel === m.id ? "border-primary bg-primary/10" : "border-border bg-card hover:border-primary/30"}`}>
                  <span className="text-xl">{m.icon}</span>
                  <div className="text-right flex-1"><div className="text-sm font-semibold">{m.name}</div>{m.badge && <span className="text-[10px] text-primary">{m.badge}</span>}</div>
                </button>
              ))}
            </div>

            <div className="bg-violet-500/5 border border-violet-500/20 rounded-xl p-3 text-xs text-violet-300 space-y-1">
              <p className="font-semibold">🖥️ تطبيق Desktop (Electron):</p>
              <p>• يعمل على Windows (EXE), macOS (DMG), Linux (AppImage)</p>
              <p>• يدعم Node.js APIs — يقدر يقرأ ملفات، يتصل بالنظام</p>
              <p>• AI يولّد الكود → تحميل مشروع Electron كامل (ZIP) جاهز للبناء</p>
              <p>• لبناء EXE: شغّل <span className="font-mono text-white">npm install && npm run build</span> على Windows</p>
            </div>

            <Button onClick={() => {
              if (desktopGenMut.isPending) return;
              if (!appName.trim()) { toast.error("أدخل اسم التطبيق"); return; }
              if (!description.trim() || description.length < 10) { toast.error("الوصف قصير"); return; }
              setStep("generating");
              desktopGenMut.mutate({ appName: appName.trim(), description: description.trim(), model: selectedModel });
            }} disabled={desktopGenMut.isPending} className="w-full py-6 text-base gap-2 bg-violet-600 hover:bg-violet-700">
              <Brain className="w-5 h-5" /> توليد مشروع Desktop
            </Button>
          </div>
        )}

        {/* ─── Mode: Upload Desktop ZIP ─────────────────────── */}
        {step === "describe" && buildMode === "desktop-upload" && (
          <div className="max-w-2xl mx-auto space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-medium">اسم التطبيق</label>
              <input value={desktopUploadName} onChange={e => setDesktopUploadName(e.target.value)} placeholder="اسم التطبيق Desktop..."
                className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50" />
            </div>

            {/* Drag-and-drop Desktop ZIP zone */}
            <div
              className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all ${
                isDragOverDesktop ? "border-violet-400 bg-violet-500/10 scale-[1.01]" :
                desktopUploadZip ? "border-emerald-500/40 bg-emerald-500/5" :
                "border-border hover:border-primary/40"
              }`}
              onClick={() => desktopUploadRef.current?.click()}
              onDragOver={e => { e.preventDefault(); setIsDragOverDesktop(true); }}
              onDragLeave={() => setIsDragOverDesktop(false)}
              onDrop={e => {
                e.preventDefault();
                setIsDragOverDesktop(false);
                const file = e.dataTransfer.files[0];
                if (file && /\.zip$/i.test(file.name)) { handleDesktopUploadFile(file); }
                else { toast.error("ZIP فقط مدعوم لمشاريع Desktop"); }
              }}
            >
              <input ref={desktopUploadRef} type="file" accept=".zip" className="hidden"
                onChange={e => { const f = e.target.files?.[0]; if (f) handleDesktopUploadFile(f); }} />
              {isDesktopExtracting ? (
                <div className="space-y-2"><Loader2 className="w-8 h-8 mx-auto animate-spin text-primary" /><p className="text-sm">جاري تحميل الملف...</p></div>
              ) : desktopUploadZip ? (
                <div className="space-y-3">
                  <Package className="w-10 h-10 mx-auto text-emerald-400" />
                  <p className="font-semibold text-emerald-300">✅ {desktopUploadFileName}</p>
                  <button onClick={e => { e.stopPropagation(); setDesktopUploadZip(""); setDesktopUploadFileName(""); }} className="text-xs text-red-400">
                    <X className="w-3 h-3 inline" /> إعادة الاختيار
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  <Upload className="w-8 h-8 mx-auto text-muted-foreground" />
                  <p className="text-sm font-medium">
                    {isDragOverDesktop ? "🎯 أسقط الملف هنا!" : "اسحب ملف ZIP أو انقر للاختيار"}
                  </p>
                  <p className="text-xs text-muted-foreground">مشروع Electron، HTML/CSS/JS، أي ملفات Desktop</p>
                </div>
              )}
            </div>

            {/* Desktop Icon Upload */}
            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <ImageIcon className="w-4 h-4 text-primary" />
                لوغو / أيقونة <span className="text-xs text-muted-foreground font-normal">(اختياري)</span>
              </label>
              <div className="flex items-center gap-3">
                <div className="w-14 h-14 rounded-xl border-2 border-dashed border-border bg-secondary/30 flex items-center justify-center overflow-hidden shrink-0 cursor-pointer hover:border-primary/50 transition-colors"
                  onClick={() => desktopIconRef.current?.click()}>
                  {desktopIconPreview ? (
                    <img src={desktopIconPreview} alt="أيقونة" className="w-full h-full object-cover rounded-xl" />
                  ) : (
                    <Upload className="w-5 h-5 text-muted-foreground/40" />
                  )}
                </div>
                <Button variant="outline" size="sm" onClick={() => desktopIconRef.current?.click()} className="gap-2 text-xs">
                  <Upload className="w-3 h-3" />
                  {desktopIconPreview ? "✅ تم رفع الأيقونة" : "رفع أيقونة (PNG / ICO)"}
                </Button>
                {desktopIconPreview && (
                  <button onClick={() => { setDesktopIconBase64(""); setDesktopIconPreview(""); }} className="text-xs text-red-400">إزالة</button>
                )}
              </div>
            </div>

            <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-3 text-xs text-blue-300 space-y-1">
              <p className="font-semibold">📦 ما يحدث عند الرفع:</p>
              <p>1. الملفات تُرفع وتُعبَّأ كمشروع Electron متكامل</p>
              <p>2. إضافة إعدادات electron-builder تلقائياً</p>
              <p>3. تحميل ZIP جاهز — شغّل <span className="font-mono text-white">npm install && npm run build</span> على Windows للحصول على EXE</p>
            </div>

            <Button onClick={() => {
              if (packageDesktopMut.isPending) return;
              if (!desktopUploadName.trim()) { toast.error("أدخل اسم التطبيق"); return; }
              if (!desktopUploadZip) { toast.error("ارفع ملف ZIP أولاً"); return; }
              packageDesktopMut.mutate({ appName: desktopUploadName.trim(), zipBase64: desktopUploadZip, iconBase64: desktopIconBase64 || undefined });
            }}
              disabled={!desktopUploadZip || !desktopUploadName.trim() || packageDesktopMut.isPending}
              className="w-full py-6 text-base gap-2 bg-blue-600 hover:bg-blue-700">
              {packageDesktopMut.isPending ? <><Loader2 className="w-5 h-5 animate-spin" /> جاري التعبئة...</> : <><Package className="w-5 h-5" /> تعبئة كمشروع Electron</>}
            </Button>
          </div>
        )}

        {/* ─── Step: Generating ─────────────────────────────── */}
        {step === "generating" && (
          <div className="max-w-md mx-auto text-center space-y-8 py-16">
            <div className="relative mx-auto w-24 h-24">
              <div className="absolute inset-0 rounded-full bg-primary/10 animate-ping" />
              <div className="relative w-24 h-24 rounded-full bg-primary/20 flex items-center justify-center">
                <Brain className="w-12 h-12 text-primary animate-pulse" />
              </div>
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold">{t("appBuilder.generatingTitle")}</h2>
              <p className="text-muted-foreground text-sm">{t("appBuilder.generatingDesc")}</p>
            </div>
            <div className="space-y-1 text-xs text-muted-foreground">
              {["تحليل المتطلبات...", "تصميم الواجهة...", "كتابة المنطق...", "مراجعة الكود..."].map((step_text, i) => (
                <div key={i} className="flex items-center gap-2 justify-center">
                  <Loader2 className="w-3 h-3 animate-spin text-primary" />
                  {step_text}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ─── Step: Review (Monaco Editor) ─────────────────── */}
        {step === "review" && (generatedCode || desktopCode) && (
          <div className="max-w-2xl mx-auto space-y-6">
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4 flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 mt-0.5 shrink-0" />
              <div>
                <p className="font-bold text-sm text-emerald-400">تم توليد الكود بنجاح!</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {buildMode === "desktop" ? "كود Electron Desktop جاهز" : "كود React Native جاهز للبناء"}
                </p>
              </div>
            </div>

            {/* Code editor toggle */}
            <button onClick={() => setShowCode(!showCode)}
              className="w-full flex items-center justify-between px-4 py-3 bg-card border border-border rounded-xl hover:border-primary/30 transition-all">
              <div className="flex items-center gap-2 text-sm font-medium">
                <Code2 className="w-4 h-4 text-primary" />
                {buildMode === "desktop" ? "app.js" : "App.tsx"} ({Math.round((generatedCode || desktopCode).length / 1000)}k حرف)
              </div>
              {showCode ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <Eye className="w-4 h-4 text-muted-foreground" />}
            </button>

            {showCode && (
              <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-secondary/30">
                  <span className="text-xs text-muted-foreground font-mono">{buildMode === "desktop" ? "app.js" : "App.tsx"} — قابل للتعديل</span>
                  <div className="flex items-center gap-2">
                    <button onClick={() => { navigator.clipboard.writeText(generatedCode || desktopCode); toast.success("تم النسخ"); }}
                      className="text-xs text-primary hover:underline">نسخ</button>
                  </div>
                </div>
                <MonacoEditor
                  height="400px"
                  language={buildMode === "desktop" ? "javascript" : "typescript"}
                  theme="vs-dark"
                  value={generatedCode || desktopCode}
                  onChange={val => {
                    if (buildMode === "desktop") setDesktopCode(val ?? "");
                    else setGeneratedCode(val ?? "");
                  }}
                  options={{
                    fontSize: 12,
                    minimap: { enabled: false },
                    wordWrap: "on",
                    scrollBeyondLastLine: false,
                    renderLineHighlight: "all",
                    lineNumbers: "on",
                    folding: true,
                    automaticLayout: true,
                    padding: { top: 12, bottom: 12 },
                  }}
                />
              </div>
            )}

            {/* AI Review Button */}
            <Button variant="outline"
              onClick={() => { if (!reviewMut.isPending) reviewMut.mutate({ code: generatedCode || desktopCode }); }}
              disabled={reviewMut.isPending}
              className="w-full gap-2 border-primary/30 text-primary">
              {reviewMut.isPending
                ? <><Loader2 className="w-4 h-4 animate-spin" /> AI يفحص الكود...</>
                : <><Brain className="w-4 h-4" /> 🔍 فحص وإصلاح بالذكاء الاصطناعي</>}
            </Button>

            {/* Build info */}
            <div className="bg-card border border-border rounded-xl p-4 space-y-3">
              <h3 className="font-bold text-sm">{buildMode === "desktop" ? "ما سيحدث:" : "ما سيحدث بعد ضغط بناء APK:"}</h3>
              <div className="space-y-2">
                {(buildMode === "desktop" ? [
                  { icon: "🤖", text: "AI يراجع الكود ويصلح الأخطاء" },
                  { icon: "📦", text: "يُنشأ مشروع Electron كامل" },
                  { icon: "💾", text: "تحميل المشروع كـ ZIP — شغّل npm run build" },
                ] : [
                  { icon: "🧠", text: "AI #1 (Claude Opus) يصلح الكود" },
                  { icon: "🔍", text: "AI #2 (Sonnet) يدقق ويتأكد" },
                  { icon: "📤", text: "رفع الكود إلى Expo EAS Cloud" },
                  { icon: "🔧", text: "بناء APK (~5-15 دقيقة)" },
                  { icon: "🔄", text: "عند الفشل — AI يحلل الخطأ ويعيد المحاولة (3 محاولات)" },
                  { icon: "📱", text: "APK جاهز للتثبيت" },
                ]).map((item, i) => (
                  <div key={i} className="flex items-center gap-3 text-sm">
                    <span>{item.icon}</span>
                    <span className="text-muted-foreground">{item.text}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex gap-3">
              <Button variant="outline" onClick={() => setStep("describe")} className="flex-1 gap-2"
                disabled={createMutation.isPending}>
                <RotateCcw className="w-4 h-4" /> تعديل
              </Button>
              {buildMode === "desktop" ? (
                <div className="flex-2 flex-grow flex flex-col gap-2">
                  <Button
                    onClick={() => {
                      if (createDesktopMut.isPending || desktopZipMut.isPending) return;
                      createDesktopMut.mutate({ appName: appName.trim() || "desktop-app", description, generatedCode: desktopCode, iconBase64: desktopIconBase64 || undefined, model: selectedModel });
                    }}
                    disabled={createDesktopMut.isPending || desktopZipMut.isPending}
                    className="w-full gap-2 bg-violet-600 hover:bg-violet-700 py-3">
                    {createDesktopMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <span>🖥️</span>}
                    {createDesktopMut.isPending ? "جاري البناء..." : "بناء تطبيق Windows (EXE)"}
                  </Button>
                  <Button variant="outline" size="sm"
                    onClick={() => {
                      if (desktopZipMut.isPending || createDesktopMut.isPending) return;
                      desktopZipMut.mutate({ appName: appName.trim() || "desktop-app", code: desktopCode, iconBase64: desktopIconBase64 || undefined });
                    }}
                    disabled={desktopZipMut.isPending || createDesktopMut.isPending}
                    className="w-full gap-2 text-xs">
                    {desktopZipMut.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
                    تحميل مشروع Electron (كود فقط)
                  </Button>
                </div>
              ) : (
                <Button onClick={handleBuild} className="flex-2 flex-grow gap-2 bg-emerald-600 hover:bg-emerald-700"
                  disabled={createMutation.isPending}>
                  {createMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Package className="w-4 h-4" />}
                  {createMutation.isPending ? "جاري الإرسال..." : t("appBuilder.buildApp")}
                </Button>
              )}
            </div>
          </div>
        )}

        {/* ─── Step: Building (with animated progress bar) ──── */}
        {step === "building" && (
          <div className="max-w-lg mx-auto text-center space-y-6 py-8">
            <div className="relative mx-auto w-28 h-28">
              <div className="absolute inset-0 rounded-full bg-indigo-500/10 animate-ping" style={{ animationDuration: "2s" }} />
              <div className="absolute inset-2 rounded-full bg-indigo-500/10 animate-ping" style={{ animationDuration: "2.5s", animationDelay: "0.3s" }} />
              <div className="relative w-28 h-28 rounded-full bg-indigo-500/20 flex items-center justify-center">
                <Cpu className="w-14 h-14 text-indigo-400" />
              </div>
            </div>

            <div className="space-y-2">
              <h2 className="text-xl font-bold">{t("appBuilder.buildingTitle")}</h2>
              <p className="text-muted-foreground text-sm">العملية تلقائية بالكامل — لا تحتاج أي تدخل</p>
            </div>

            {/* Animated Progress Bar */}
            <div className="bg-card border border-border rounded-xl p-4 space-y-3 text-right">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-muted-foreground">الوقت المنقضي: {Math.floor(buildElapsed / 60)}:{String(buildElapsed % 60).padStart(2, "0")}</span>
                <span className="text-indigo-400 font-mono font-bold">{progressPct}%</span>
              </div>
              <div className="w-full h-2 bg-secondary rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-indigo-500 to-emerald-500 rounded-full transition-all duration-1000"
                  style={{ width: `${progressPct}%` }}
                />
              </div>
              <p className="text-[10px] text-muted-foreground text-center">الوقت المتوقع: 5-15 دقيقة — ({MAX_POLL_RETRIES - pollCount.current} فحص متبقٍ)</p>
            </div>

            {/* Visual Pipeline */}
            <div className="bg-card border border-border rounded-xl p-4 space-y-3 text-right">
              <div className="text-xs font-semibold text-muted-foreground mb-2">مراحل البناء التلقائي:</div>
              {[
                { icon: "🧠", label: "AI #1 (Claude Opus) يصلح الكود",   status: "done" },
                { icon: "🔍", label: "AI #2 (Sonnet) يدقق ويؤكد",        status: "done" },
                { icon: "📦", label: "إنشاء مشروع Expo",                 status: "done" },
                { icon: "📤", label: "رفع لـ Expo EAS Cloud",
                  status: buildData?.status === "building" || buildData?.status === "in_progress" ? "done" : buildData ? "done" : "active" },
                { icon: "🔧", label: "بناء APK على السحابة",
                  status: buildData?.status === "building" || buildData?.status === "in_progress" ? "active" : buildData?.status === "finished" ? "done" : "waiting" },
                { icon: "✅", label: "جاهز للتحميل",
                  status: buildData?.status === "finished" ? "done" : "waiting" },
              ].map((stage, i) => (
                <div key={i} className={`flex items-center gap-3 text-sm py-1.5 ${
                  stage.status === "active" ? "text-primary" : stage.status === "done" ? "text-emerald-400" : "text-muted-foreground/40"
                }`}>
                  <span className="text-base w-6">{stage.icon}</span>
                  <span className={stage.status === "active" ? "font-semibold" : ""}>{stage.label}</span>
                  <span className="mr-auto">
                    {stage.status === "done"    ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> :
                     stage.status === "active"  ? <Loader2 className="w-4 h-4 animate-spin text-primary" /> :
                     <Clock className="w-4 h-4 text-muted-foreground/30" />}
                  </span>
                </div>
              ))}
              {buildData?.status === "errored" && (
                <div className="flex items-center gap-3 text-sm py-1.5 text-amber-400">
                  <span className="text-base w-6">🔄</span>
                  <span className="font-semibold">AI #1 يصلح + AI #2 يدقق ثم يعاد الإرسال...</span>
                  <Loader2 className="w-4 h-4 animate-spin mr-auto" />
                </div>
              )}
            </div>

            {buildData && (
              <div className="bg-card border border-border rounded-xl p-4 space-y-2 text-right">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">الحالة</span>
                  <span className={statusLabel(buildData.status).color}>{statusLabel(buildData.status).label}</span>
                </div>
                {buildData.buildLogsUrl && (
                  <a href={buildData.buildLogsUrl} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-1 text-primary hover:underline text-xs justify-end">
                    عرض السجلات <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            )}

            <div className="flex gap-3">
              <Button variant="outline"
                onClick={() => { if (!syncMutation.isPending && currentBuildId) syncMutation.mutate({ buildId: currentBuildId }); }}
                disabled={syncMutation.isPending} className="flex-1 gap-2">
                {syncMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                تحديث
              </Button>
              {buildData?.buildLogsUrl && (
                <a href={buildData.buildLogsUrl} target="_blank" rel="noopener noreferrer" className="flex-1">
                  <Button variant="outline" className="w-full gap-2">
                    <ExternalLink className="w-4 h-4" /> تفاصيل
                  </Button>
                </a>
              )}
            </div>

            <p className="text-xs text-muted-foreground">تحديث تلقائي كل 10 ثوانٍ — عند الفشل AI يصلح ويعيد المحاولة تلقائياً</p>
          </div>
        )}

        {/* ─── Step: Done ───────────────────────────────────── */}
        {step === "done" && buildData && (
          <div className="max-w-3xl mx-auto space-y-6 py-8">
            <div className="text-center space-y-2">
              <div className="relative mx-auto w-20 h-20">
                <div className="absolute inset-0 rounded-full bg-emerald-500/20 animate-ping" style={{ animationDuration: "3s" }} />
                <div className="relative w-20 h-20 rounded-full bg-emerald-500/20 flex items-center justify-center">
                  <CheckCircle2 className="w-10 h-10 text-emerald-400" />
                </div>
              </div>
              <h2 className="text-2xl font-bold">🎉 تم بناء التطبيق!</h2>
              <p className="text-muted-foreground">{buildData.appName || appName}</p>
            </div>

            {(() => {
              const isWindows = buildData.platform === "windows";
              return (
                <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-6">
                  <div className="flex flex-col items-center gap-4">
                    {isWindows ? (
                      <div className="relative w-[220px] h-[160px] bg-gray-900 rounded-xl border-4 border-gray-700 shadow-2xl shadow-black/50 flex flex-col items-center justify-center gap-2">
                        <div className="text-5xl">🖥️</div>
                        <p className="text-white font-bold text-sm">{buildData.appName || appName}</p>
                        <div className="px-3 py-1 bg-violet-500/20 rounded-full text-violet-400 text-[10px]">Windows EXE ✅</div>
                      </div>
                    ) : (
                      <div className="relative w-[220px] h-[440px] bg-black rounded-[2.5rem] p-2 border-4 border-gray-700 shadow-2xl shadow-black/50">
                        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-24 h-5 bg-black rounded-b-2xl z-10" />
                        <div className="w-full h-full bg-gradient-to-b from-[#1a1a2e] to-[#16213e] rounded-[2rem] overflow-hidden flex flex-col items-center justify-center text-center p-4">
                          {iconPreview ? (
                            <img src={iconPreview} alt="icon" className="w-16 h-16 rounded-2xl mb-3 shadow-lg" />
                          ) : (
                            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-primary/30 to-emerald-500/30 flex items-center justify-center mb-3 text-3xl">📱</div>
                          )}
                          <p className="text-white font-bold text-sm">{buildData.appName || appName}</p>
                          <p className="text-white/40 text-[10px] mt-1">HAYO AI Builder</p>
                          <div className="mt-4 px-3 py-1.5 bg-emerald-500/20 rounded-full text-emerald-400 text-[10px]">✅ جاهز للتثبيت</div>
                        </div>
                      </div>
                    )}
                    {buildData.downloadUrl && !isWindows && (
                      <div className="bg-card border border-border rounded-xl p-3 text-center space-y-2">
                        <img src={`https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${encodeURIComponent(buildData.downloadUrl)}`} alt="QR" className="mx-auto rounded-lg" width={120} height={120} />
                        <p className="text-[10px] text-muted-foreground">امسح للتحميل على هاتفك</p>
                      </div>
                    )}
                  </div>

                  <div className="space-y-4">
                    <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                      <h3 className="font-bold text-sm">معلومات التطبيق</h3>
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div className="bg-muted/30 rounded-lg p-2"><span className="text-muted-foreground">الاسم</span><div className="font-semibold mt-0.5">{buildData.appName || appName}</div></div>
                        <div className="bg-muted/30 rounded-lg p-2"><span className="text-muted-foreground">المنصة</span><div className="font-semibold mt-0.5">{isWindows ? "Windows EXE" : "Android APK"}</div></div>
                        <div className="bg-muted/30 rounded-lg p-2"><span className="text-muted-foreground">الحالة</span><div className="font-semibold mt-0.5 text-emerald-400">مكتمل ✅</div></div>
                        <div className="bg-muted/30 rounded-lg p-2"><span className="text-muted-foreground">التاريخ</span><div className="font-semibold mt-0.5">{new Date().toLocaleDateString("ar-SA")}</div></div>
                      </div>
                      {!isWindows && keystoreBase64 && <div className="text-xs text-emerald-400 flex items-center gap-1.5"><CheckCircle2 className="w-3 h-3" /> موقّع بشهادتك الخاصة</div>}
                      {!isWindows && supabaseUrl && <div className="text-xs text-blue-400 flex items-center gap-1.5"><CheckCircle2 className="w-3 h-3" /> متصل بـ Supabase</div>}
                      {dataFiles.length > 0 && <div className="text-xs text-violet-400 flex items-center gap-1.5"><CheckCircle2 className="w-3 h-3" /> {dataFiles.length} ملف بيانات مدمج</div>}
                    </div>

                    <div className="bg-card border border-emerald-500/40 rounded-xl p-4 space-y-3">
                      {buildData.downloadUrl ? (
                        <>
                          <a href={buildData.downloadUrl} download={isWindows} rel="noopener noreferrer">
                            <Button className={`w-full py-5 text-lg gap-3 rounded-xl shadow-lg ${isWindows ? "bg-violet-600 hover:bg-violet-700 shadow-violet-900/30" : "bg-emerald-600 hover:bg-emerald-700 shadow-emerald-900/30"}`}>
                              <Download className="w-6 h-6" /> {isWindows ? "تحميل تطبيق Windows (ZIP)" : "تحميل APK"}
                            </Button>
                          </a>
                          <div className="flex gap-2">
                            <button onClick={() => { navigator.clipboard.writeText(buildData.downloadUrl!); toast.success("تم نسخ الرابط ✅"); }}
                              className="flex-1 text-xs text-muted-foreground hover:text-foreground flex items-center justify-center gap-1.5 py-2 bg-muted/30 rounded-lg">
                              <ExternalLink className="w-3 h-3" /> نسخ الرابط
                            </button>
                            {buildData.buildLogsUrl && (
                              <a href={buildData.buildLogsUrl} target="_blank" rel="noopener noreferrer" className="flex-1">
                                <button className="w-full text-xs text-muted-foreground hover:text-foreground flex items-center justify-center gap-1.5 py-2 bg-muted/30 rounded-lg">
                                  <Eye className="w-3 h-3" /> سجلات البناء
                                </button>
                              </a>
                            )}
                          </div>
                        </>
                      ) : (
                        <div className="space-y-3 text-center">
                          <p className="text-sm text-amber-400">جاري تحضير الرابط...</p>
                          <Button variant="ghost" size="sm" className="gap-2"
                            onClick={() => { if (!syncMutation.isPending && currentBuildId) syncMutation.mutate({ buildId: currentBuildId }); }}>
                            <RefreshCw className={`w-3 h-3 ${syncMutation.isPending ? "animate-spin" : ""}`} /> تحديث
                          </Button>
                        </div>
                      )}
                    </div>

                    <div className="bg-muted/20 rounded-xl p-3 text-xs text-right space-y-1.5 text-muted-foreground">
                      {isWindows ? (
                        <>
                          <p className="font-semibold text-foreground">🖥️ تثبيت Windows:</p>
                          <p>① حمّل ملف ZIP ② فكّه ③ شغّل ملف EXE الموجود داخل المجلد 🎊</p>
                        </>
                      ) : (
                        <>
                          <p className="font-semibold text-foreground">📱 تثبيت APK:</p>
                          <p>① حمّل الملف ② افتحه من الإشعارات ③ فعّل "مصادر غير معروفة" إذا طُلب ④ أكمل التثبيت 🎊</p>
                        </>
                      )}
                    </div>

                    <Button variant="outline" onClick={handleReset} className="w-full gap-2">
                      <Sparkles className="w-4 h-4" /> بناء تطبيق جديد
                    </Button>
                  </div>
                </div>
              );
            })()}
          </div>
        )}

        {/* ─── Step: Error (with retry + error details) ─────── */}
        {step === "error" && (
          <div className="max-w-md mx-auto text-center space-y-6 py-8">
            <div className="w-24 h-24 mx-auto rounded-full bg-red-500/20 flex items-center justify-center">
              <AlertCircle className="w-12 h-12 text-red-400" />
            </div>
            <div className="space-y-3">
              <h2 className="text-xl font-bold">{t("appBuilder.errorTitle")}</h2>
              {buildData?.errorMessage && (
                <div className="text-right">
                  <p className="text-xs text-muted-foreground mb-1">تفاصيل الخطأ:</p>
                  <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg p-3 font-mono text-right leading-relaxed">
                    {buildData.errorMessage}
                  </p>
                </div>
              )}
            </div>

            {/* Error action buttons */}
            <div className="space-y-3">
              {/* Retry with same code */}
              {lastBuildInput && (
                <Button
                  onClick={handleRetryBuild}
                  disabled={createMutation.isPending}
                  className="w-full gap-2 bg-indigo-600 hover:bg-indigo-700">
                  {createMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                  {createMutation.isPending ? "جاري إعادة المحاولة..." : "🔄 إعادة البناء (نفس الكود)"}
                </Button>
              )}

              {/* AI Debug */}
              {generatedCode && (
                <Button variant="outline" className="w-full gap-2 border-primary/30 text-primary"
                  onClick={() => { if (!reviewMut.isPending) reviewMut.mutate({ code: generatedCode, errorLog: buildData?.errorMessage || "" }); }}
                  disabled={reviewMut.isPending}>
                  {reviewMut.isPending
                    ? <><Loader2 className="w-4 h-4 animate-spin" /> AI يحلل الخطأ...</>
                    : <><Brain className="w-4 h-4" /> 🔧 AI Debug — تحليل وإصلاح تلقائي</>}
                </Button>
              )}

              {reviewMut.isSuccess && (
                <Button onClick={() => { setStep("review"); toast.success("✅ تم الإصلاح — راجع الكود وأعد البناء"); }} className="w-full gap-2 bg-emerald-600">
                  <Eye className="w-4 h-4" /> مراجعة الكود المُصلح
                </Button>
              )}

              {buildData?.buildLogsUrl && (
                <a href={buildData.buildLogsUrl} target="_blank" rel="noopener noreferrer">
                  <Button variant="outline" className="w-full gap-2">
                    <ExternalLink className="w-4 h-4" />
                    عرض سجلات الخطأ الكاملة
                  </Button>
                </a>
              )}

              <Button onClick={handleReset} variant="ghost" className="w-full gap-2">
                <RotateCcw className="w-4 h-4" />
                بدء من الصفر
              </Button>
            </div>
          </div>
        )}

        {/* ─── Build History (Enhanced) ─────────────────────── */}
        {buildsList.length > 0 && step === "describe" && (
          <div className="space-y-4">
            {/* History header with collapse toggle */}
            <div className="flex items-center justify-between">
              <button onClick={() => setHistoryCollapsed(p => !p)}
                className="flex items-center gap-2 text-sm font-bold hover:text-primary transition-colors">
                <History className="w-4 h-4 text-primary" />
                {t("appBuilder.history")}
                <span className="text-xs text-muted-foreground font-normal">({buildsList.length})</span>
                {historyCollapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
              </button>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                {successBuilds > 0 && <span className="text-emerald-400">{successBuilds} ناجح</span>}
                {failedBuilds > 0 && <span className="text-red-400">{failedBuilds} فاشل</span>}
              </div>
            </div>

            {!historyCollapsed && (
              <>
                {/* Search + Filter bar */}
                <div className="flex gap-2 flex-wrap">
                  <div className="relative flex-1 min-w-[180px]">
                    <Search className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                    <input
                      value={historySearch}
                      onChange={e => setHistorySearch(e.target.value)}
                      placeholder="بحث باسم التطبيق..."
                      className="w-full bg-card border border-border rounded-lg pr-9 pl-3 py-2 text-xs focus:outline-none focus:ring-1 focus:ring-primary/50"
                    />
                  </div>
                  <div className="flex gap-1">
                    {(["all", "finished", "errored", "building"] as const).map(f => (
                      <button key={f} onClick={() => setHistoryFilter(f)}
                        className={`px-2.5 py-1.5 rounded-lg text-[10px] font-medium border transition-all ${
                          historyFilter === f
                            ? "bg-primary/15 border-primary text-primary"
                            : "bg-card border-border text-muted-foreground hover:border-primary/30"
                        }`}>
                        {f === "all" ? "الكل" : f === "finished" ? "✅ ناجح" : f === "errored" ? "❌ فاشل" : "⏳ جاري"}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Build list */}
                {filteredBuilds.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground text-sm">لا توجد نتائج</div>
                ) : (
                  <div className="space-y-2">
                    {filteredBuilds.map(build => {
                      const s          = statusLabel(build.status);
                      const StatusIcon = s.icon;
                      const isActive   = build.status === "building" || build.status === "in_progress" || build.status === "submitting";
                      const createdDate = new Date(build.createdAt);
                      const updatedDate = build.updatedAt ? new Date(build.updatedAt) : null;
                      const durationMs  = updatedDate && build.status === "finished"
                        ? updatedDate.getTime() - createdDate.getTime() : null;
                      const durationMin = durationMs ? Math.round(durationMs / 60000) : null;

                      return (
                        <div key={build.id}
                          className="bg-card border border-border rounded-xl p-4 hover:border-primary/20 transition-all">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                                build.status === "finished" ? "bg-emerald-500/15" :
                                build.status === "errored"  ? "bg-red-500/15" :
                                "bg-secondary/50"
                              }`}>
                                <Smartphone className={`w-5 h-5 ${
                                  build.status === "finished" ? "text-emerald-400" :
                                  build.status === "errored"  ? "text-red-400" :
                                  "text-muted-foreground"
                                }`} />
                              </div>
                              <div>
                                <p className="font-medium text-sm">{build.appName}</p>
                                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                  <span>{createdDate.toLocaleDateString("ar-SA")}</span>
                                  {durationMin !== null && <span>• {durationMin} دقيقة</span>}
                                  {build.platform && <span>• {build.platform === "android" ? "Android" : "Windows"}</span>}
                                </div>
                              </div>
                            </div>

                            <div className="flex items-center gap-2">
                              <span className={`flex items-center gap-1 text-xs font-medium ${s.color}`}>
                                <StatusIcon className={`w-3 h-3 ${isActive ? "animate-spin" : ""}`} />
                                {s.label}
                              </span>
                              {build.downloadUrl && (
                                <a href={build.downloadUrl} target="_blank" rel="noopener noreferrer">
                                  <Button size="sm" className="text-xs gap-1 bg-emerald-600 hover:bg-emerald-700 h-7 px-2">
                                    <Download className="w-3 h-3" /> تحميل
                                  </Button>
                                </a>
                              )}
                              {!build.downloadUrl && isActive && (
                                <Button size="sm" variant="outline" className="text-xs gap-1 h-7 px-2"
                                  onClick={async () => {
                                    const updated = await syncMutation.mutateAsync({ buildId: build.id });
                                    if (updated && (updated as BuildSyncResponse).downloadUrl) {
                                      toast.success("✅ تم تحديث البناء — رابط التحميل جاهز!", { duration: 5000 });
                                      refetchBuilds();
                                    }
                                  }}
                                  disabled={syncMutation.isPending}>
                                  <RefreshCw className={`w-3 h-3 ${syncMutation.isPending ? "animate-spin" : ""}`} />
                                  تحديث
                                </Button>
                              )}
                              {build.buildLogsUrl && !build.downloadUrl && !isActive && (
                                <a href={build.buildLogsUrl} target="_blank" rel="noopener noreferrer">
                                  <Button size="sm" variant="outline" className="text-xs gap-1 h-7 px-2">
                                    <ExternalLink className="w-3 h-3" /> تفاصيل
                                  </Button>
                                </a>
                              )}
                              {/* Delete button */}
                              <button
                                onClick={() => {
                                  if (deleteBuildMut.isPending) return;
                                  if (window.confirm(`حذف بناء "${build.appName}"؟`)) {
                                    deleteBuildMut.mutate({ buildId: build.id });
                                  }
                                }}
                                disabled={deleteBuildMut.isPending}
                                className="p-1.5 rounded-lg text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors"
                                title="حذف">
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
