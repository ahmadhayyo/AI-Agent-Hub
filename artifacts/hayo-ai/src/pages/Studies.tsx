/**
 * HAYO THINK — المستشار الاستراتيجي الذكي
 * Route: /studies
 * 4 categories: Engineering, Commerce, Investment, General
 * Powered by callPowerAI (Claude Opus → Gemini → Sonnet → DeepSeek)
 */

import { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { toast } from "sonner";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import {
  Home, Building2, TrendingUp, BarChart3, Lightbulb, Brain,
  Loader2, Download, Copy, RefreshCw, MessageSquare, Send,
  ChevronDown, ExternalLink, CheckCircle, Sparkles, X, Info,
  FileImage, FileCode2, ImageDown,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";

const API_BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

// ─── Types ─────────────────────────────────────────────────────────────
type Category = "engineering" | "commerce" | "investment" | "medical" | "tech" | "agriculture" | "general";
type DetailLevel = "summary" | "standard" | "detailed";

interface CategoryConfig {
  id: Category;
  label: string;
  icon: React.ElementType;
  emoji: string;
  gradient: string;
  border: string;
  desc: string;
  subcategories: string[];
  examples: string[];
  tools?: { label: string; url: string; desc: string }[];
}

// ─── Category Config ────────────────────────────────────────────────────
const CATEGORIES: CategoryConfig[] = [
  {
    id: "engineering",
    label: "هندسة وبناء",
    icon: Building2,
    emoji: "🏗️",
    gradient: "from-blue-600 to-cyan-500",
    border: "border-blue-500/30",
    desc: "مخططات معمارية، حسابات إنشائية، كميات مواد، تقديرات تكلفة",
    subcategories: ["بناء سكني / عمارة", "فيلا أو منزل", "مبنى تجاري / مكاتب", "مصنع أو مستودع", "مدرسة أو مستشفى", "مسجد", "منشأة صناعية", "أخرى"],
    examples: [
      "أرض 400م² — عمارة 5 طوابق — كل طابق شقتين — منطقة زلزالية",
      "فيلا 350م² — طابقين — 5 غرف نوم — مسبح وحديقة — تشطيب فاخر",
      "مستودع صناعي 800م² — ارتفاع 9م — باب شاحنات — جسر رافعة",
      "عمارة تجارية 200م² — 3 طوابق — محلات أرضي ومكاتب فوق",
    ],
    tools: [
      { label: "Planner 5D", url: "https://planner5d.com/ar/", desc: "مخطط 2D/3D مجاني بالعربية" },
      { label: "RoomSketcher", url: "https://www.roomsketcher.com/", desc: "مخطط احترافي عبر الإنترنت" },
      { label: "Floorplanner", url: "https://floorplanner.com/", desc: "تصميم مخططات بسهولة" },
      { label: "AutoCAD Web", url: "https://web.autocad.com/", desc: "AutoDesk المهني مجاناً" },
    ],
  },
  {
    id: "commerce",
    label: "تجارة ومحاسبة",
    icon: TrendingUp,
    emoji: "💰",
    gradient: "from-emerald-500 to-green-500",
    border: "border-emerald-500/30",
    desc: "خطط أعمال، ميزانيات، تدفق نقدي، تحليل SWOT، نقطة التعادل",
    subcategories: ["سوبرماركت / بقالة", "مطعم / كافيه", "صيدلية", "متجر ملابس", "محطة وقود", "شركة خدمات", "استيراد وتصدير", "تجارة إلكترونية", "أخرى"],
    examples: [
      "سوبرماركت متوسط مساحة 200م² في حي سكني — رأس مال 60,000$",
      "مطعم شاورما وأكلات سريعة — مساحة 120م² — شارع رئيسي",
      "صيدلية في منطقة سكنية — رأس مال 40,000$ — مع مستودع صغير",
      "شركة برمجيات ومشاريع تقنية — 8 موظفين — عمل هجين",
    ],
  },
  {
    id: "investment",
    label: "دراسات جدوى",
    icon: BarChart3,
    emoji: "📊",
    gradient: "from-purple-500 to-violet-600",
    border: "border-purple-500/30",
    desc: "NPV، IRR، ROI، تحليل حساسية، دراسة سوق، خطط تمويل",
    subcategories: ["مشروع عقاري (بيع/إيجار)", "مشروع زراعي", "مشروع صناعي", "مشروع سياحي / فندقي", "مشروع تقني / تطبيق", "طاقة متجددة", "تعليم وتدريب", "أخرى"],
    examples: [
      "مجمع سكني 20 شقة للبيع — ضاحية مدينة كبرى — استثمار 2 مليون$",
      "مزرعة طماطم وخيار 5 هكتار — ري بالتنقيط — للتصدير",
      "فندق بوتيك 30 غرفة — منطقة سياحية — 3 نجوم",
      "تطبيق توصيل طعام — سوق محلي — 100,000 مستخدم مستهدف",
    ],
  },
  {
    id: "medical",
    label: "صحة وطب",
    icon: Building2,
    emoji: "🏥",
    gradient: "from-red-500 to-pink-500",
    border: "border-red-500/30",
    desc: "مستشفيات، عيادات، مختبرات، صيدليات، مراكز تأهيل، مشاريع صحية",
    subcategories: ["مستشفى خاص", "عيادة تخصصية", "مركز أسنان", "مختبر طبي", "صيدلية", "مركز تأهيل وعلاج طبيعي", "مركز أشعة وتصوير", "عيادة تجميل", "أخرى"],
    examples: [
      "عيادة أسنان متخصصة — 3 كراسي — حي سكني 80,000 نسمة",
      "مختبر تحاليل طبية شامل — في مبنى تجاري — رأس مال 120,000$",
      "مركز علاج طبيعي وتأهيل — 8 أسرّة — بالقرب من مستشفى كبير",
      "صيدلية مع قسم مستحضرات تجميل — شارع رئيسي — مساحة 100م²",
    ],
    tools: [
      { label: "WHO Data", url: "https://data.who.int/", desc: "بيانات منظمة الصحة العالمية" },
      { label: "PubMed", url: "https://pubmed.ncbi.nlm.nih.gov/", desc: "أبحاث طبية محكّمة" },
    ],
  },
  {
    id: "tech",
    label: "تقنية وبرمجيات",
    icon: Lightbulb,
    emoji: "💻",
    gradient: "from-indigo-500 to-blue-500",
    border: "border-indigo-500/30",
    desc: "تطبيقات، منصات SaaS، ذكاء اصطناعي، تجارة إلكترونية، بنية تحتية تقنية",
    subcategories: ["تطبيق موبايل", "منصة SaaS", "متجر إلكتروني", "تطبيق ذكاء اصطناعي", "بنية تحتية سحابية", "نظام ERP / CRM", "لعبة إلكترونية", "تطبيق FinTech", "أخرى"],
    examples: [
      "تطبيق توصيل طعام — 100,000 مستخدم مستهدف — سوق محلي",
      "منصة SaaS لإدارة المطاعم — اشتراك شهري — 500 مطعم مستهدف",
      "تطبيق ذكاء اصطناعي لتحليل صور طبية — B2B — مستشفيات",
      "متجر إلكتروني للأزياء — 10,000 منتج — شحن دولي",
    ],
    tools: [
      { label: "Product Hunt", url: "https://www.producthunt.com/", desc: "اكتشاف منتجات تقنية مشابهة" },
      { label: "Crunchbase", url: "https://www.crunchbase.com/", desc: "بيانات الشركات والاستثمارات" },
    ],
  },
  {
    id: "agriculture",
    label: "زراعة وثروة حيوانية",
    icon: Lightbulb,
    emoji: "🌾",
    gradient: "from-green-500 to-lime-500",
    border: "border-green-500/30",
    desc: "مزارع، دواجن، مواشي، أسماك، بيوت محمية، ري، تصنيع غذائي",
    subcategories: ["مزرعة خضار/فواكه", "دواجن لاحم/بيّاض", "مواشي (أبقار/أغنام)", "استزراع سمكي", "بيوت محمية", "زراعة مائية (Hydroponics)", "نحل وعسل", "تصنيع غذائي", "أخرى"],
    examples: [
      "مزرعة دجاج لاحم 10,000 طير — حظيرتين — منطقة ريفية",
      "بيوت محمية 10 وحدات — طماطم وفلفل — ري بالتنقيط",
      "مشروع استزراع سمكي — 8 أحواض — بلطي — 50 طن/سنة",
      "مزرعة زيتون 20 هكتار — 3000 شجرة — إنتاج زيت عضوي",
    ],
    tools: [
      { label: "FAO Data", url: "https://www.fao.org/faostat/", desc: "بيانات الزراعة العالمية" },
    ],
  },
  {
    id: "general",
    label: "دراسات عامة",
    icon: Lightbulb,
    emoji: "🔬",
    gradient: "from-amber-500 to-orange-500",
    border: "border-amber-500/30",
    desc: "صناعة، تعليم، بيئة، طاقة، نقل، أي مجال آخر",
    subcategories: ["صناعة وتصنيع", "تعليم وتدريب", "طاقة متجددة", "بيئة واستدامة", "نقل ولوجستيات", "سياحة وضيافة", "إعلام ونشر", "أخرى"],
    examples: [
      "مصنع علب بلاستيكية — طاقة 500,000 قطعة/شهر — استثمار 800,000$",
      "أكاديمية برمجة وتصميم — 3 فروع — نظام الامتياز (Franchise)",
      "محطة طاقة شمسية 5 ميغاواط — أرض صحراوية 10 هكتار",
      "وكالة إعلان رقمي — 15 موظف — خدمات سوشيال ميديا",
    ],
  },
];

// ─── Loading Messages ───────────────────────────────────────────────────
const LOADING_MSGS: Record<Category, string[]> = {
  engineering: [
    "جاري تحليل المتطلبات الهندسية...",
    "جاري حساب الكميات والمواد...",
    "جاري إعداد المخططات المعمارية...",
    "جاري حساب التكاليف التفصيلية...",
    "جاري توليد تقرير هندسي شامل...",
  ],
  commerce: [
    "جاري دراسة السوق المستهدف...",
    "جاري حساب التكاليف والإيرادات...",
    "جاري تحليل نقطة التعادل...",
    "جاري إعداد التدفقات النقدية...",
    "جاري توليد الخطة التجارية...",
  ],
  investment: [
    "جاري تقييم المشروع الاستثماري...",
    "جاري احتساب NPV و IRR...",
    "جاري إجراء تحليل الحساسية...",
    "جاري تقييم المخاطر والفرص...",
    "جاري توليد دراسة الجدوى...",
  ],
  medical: [
    "جاري تحليل السوق الصحي...",
    "جاري حساب تكاليف المعدات الطبية...",
    "جاري دراسة المتطلبات التنظيمية...",
    "جاري إعداد الكادر الطبي والمالية...",
    "جاري إنشاء الدراسة الصحية الشاملة...",
  ],
  tech: [
    "جاري تحليل المنافسين التقنيين...",
    "جاري تصميم البنية المعمارية...",
    "جاري حساب تكاليف التطوير...",
    "جاري إعداد خارطة المنتج...",
    "جاري إنشاء الدراسة التقنية...",
  ],
  agriculture: [
    "جاري تحليل التربة والمناخ...",
    "جاري حساب الطاقة الإنتاجية...",
    "جاري تقدير تكاليف المعدات...",
    "جاري إعداد الخطة الزراعية...",
    "جاري إنشاء الدراسة الزراعية...",
  ],
  general: [
    "جاري تحليل المتطلبات...",
    "جاري جمع البيانات والأرقام...",
    "جاري إعداد الدراسة الشاملة...",
    "جاري مراجعة التوصيات...",
    "جاري إنهاء التقرير...",
  ],
};

// ─── SVG Floor Plan Extractor ───────────────────────────────────────────
function extractFloorPlan(text: string): { svg: string; rest: string } | null {
  const match = text.match(/<FLOOR_PLAN>([\s\S]*?)<\/FLOOR_PLAN>/);
  if (!match) return null;
  const svg = match[1].trim();
  const rest = text.replace(/<FLOOR_PLAN>[\s\S]*?<\/FLOOR_PLAN>/, "").trim();
  return { svg, rest };
}

// ─── Markdown Renderer ──────────────────────────────────────────────────
function StudyMarkdown({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h1: ({ children }) => (
          <h1 className="text-2xl font-bold text-white mt-8 mb-4 pb-2 border-b border-violet-500/30">{children}</h1>
        ),
        h2: ({ children }) => (
          <h2 className="text-xl font-bold text-violet-300 mt-7 mb-3 flex items-center gap-2">
            <span className="w-1 h-5 bg-violet-500 rounded-full inline-block" />
            {children}
          </h2>
        ),
        h3: ({ children }) => (
          <h3 className="text-base font-semibold text-blue-300 mt-5 mb-2">{children}</h3>
        ),
        h4: ({ children }) => (
          <h4 className="text-sm font-semibold text-white/80 mt-4 mb-1">{children}</h4>
        ),
        p: ({ children }) => (
          <p className="text-white/80 leading-relaxed mb-3 text-sm">{children}</p>
        ),
        ul: ({ children }) => (
          <ul className="space-y-1.5 mb-4 pr-2">{children}</ul>
        ),
        ol: ({ children }) => (
          <ol className="space-y-1.5 mb-4 pr-2 list-decimal list-inside">{children}</ol>
        ),
        li: ({ children }) => (
          <li className="text-white/75 text-sm flex items-start gap-2">
            <span className="text-violet-400 mt-1 shrink-0">•</span>
            <span>{children}</span>
          </li>
        ),
        table: ({ children }) => (
          <div className="overflow-x-auto my-5 rounded-xl border border-white/10">
            <table className="w-full text-sm">{children}</table>
          </div>
        ),
        thead: ({ children }) => (
          <thead className="bg-violet-500/15">{children}</thead>
        ),
        th: ({ children }) => (
          <th className="px-4 py-2.5 text-right text-white/90 font-semibold text-xs border-b border-white/10">{children}</th>
        ),
        td: ({ children }) => (
          <td className="px-4 py-2 text-right text-white/75 text-xs border-b border-white/5">{children}</td>
        ),
        tr: ({ children }) => (
          <tr className="hover:bg-white/3 transition-colors">{children}</tr>
        ),
        blockquote: ({ children }) => (
          <blockquote className="border-r-4 border-violet-500 pr-4 my-4 bg-violet-500/5 py-3 rounded-l-lg text-white/70 text-sm">{children}</blockquote>
        ),
        code: ({ children, className }) => {
          const isBlock = className?.includes("language-");
          if (isBlock) {
            return (
              <pre className="bg-black/40 border border-white/10 rounded-xl p-4 overflow-x-auto my-4">
                <code className="text-emerald-300 text-xs font-mono">{children}</code>
              </pre>
            );
          }
          return <code className="bg-white/10 text-violet-300 px-1.5 py-0.5 rounded text-xs font-mono">{children}</code>;
        },
        strong: ({ children }) => (
          <strong className="text-white font-semibold">{children}</strong>
        ),
        hr: () => <hr className="border-white/10 my-6" />,
      }}
    >
      {content}
    </ReactMarkdown>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────
export default function Studies() {
  const [selectedCat, setSelectedCat]     = useState<Category | null>(null);
  const [subcategory, setSubcategory]     = useState("");
  const [userInput, setUserInput]         = useState("");
  const [detailLevel, setDetailLevel]     = useState<DetailLevel>("standard");
  const [isGenerating, setIsGenerating]   = useState(false);
  const [study, setStudy]                 = useState<string | null>(null);
  const [studyClean, setStudyClean]       = useState<string | null>(null);
  const [svgPlan, setSvgPlan]             = useState<string | null>(null);
  const [modelUsed, setModelUsed]         = useState<string | null>(null);
  const [loadingMsg, setLoadingMsg]       = useState("");
  const [msgIdx, setMsgIdx]               = useState(0);
  const [followUpQ, setFollowUpQ]         = useState("");
  const [followUpA, setFollowUpA]         = useState<string | null>(null);
  const [isFULoading, setIsFULoading]     = useState(false);
  const [showFloorPlan, setShowFloorPlan] = useState(true);
  const [copied, setCopied]               = useState(false);
  const [followUpCopied, setFollowUpCopied] = useState(false);
  const [svgCopied, setSvgCopied]         = useState(false);
  const resultRef = useRef<HTMLDivElement>(null);
  const floorPlanRef = useRef<HTMLDivElement>(null);
  const loadingTimer = useRef<ReturnType<typeof setInterval>>();

  const catConfig = CATEGORIES.find(c => c.id === selectedCat);

  // Cycle loading messages
  useEffect(() => {
    if (isGenerating && selectedCat) {
      const msgs = LOADING_MSGS[selectedCat];
      setLoadingMsg(msgs[0]);
      setMsgIdx(0);
      loadingTimer.current = setInterval(() => {
        setMsgIdx(prev => {
          const next = (prev + 1) % msgs.length;
          setLoadingMsg(msgs[next]);
          return next;
        });
      }, 3500);
    } else {
      if (loadingTimer.current) clearInterval(loadingTimer.current);
    }
    return () => { if (loadingTimer.current) clearInterval(loadingTimer.current); };
  }, [isGenerating, selectedCat]);

  // Scroll to result when ready
  useEffect(() => {
    if (study && resultRef.current) {
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
    }
  }, [study]);

  const handleGenerate = async () => {
    if (!userInput.trim()) { toast.error("أدخل وصفاً للمشروع أولاً"); return; }
    if (!selectedCat) { toast.error("اختر تصنيف الدراسة أولاً"); return; }
    setIsGenerating(true);
    setStudy(null);
    setStudyClean(null);
    setSvgPlan(null);
    setFollowUpA(null);
    setModelUsed(null);

    try {
      const res = await fetch(`${API_BASE}/api/studies/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ category: selectedCat, subcategory, userInput, detailLevel }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "فشل الإنشاء");

      setModelUsed(data.modelUsed);
      const rawStudy = data.study as string;

      // Extract SVG diagrams from all categories that produce them
      const diagramCategories = ["engineering", "medical", "tech", "agriculture"];
      if (selectedCat && diagramCategories.includes(selectedCat)) {
        const extracted = extractFloorPlan(rawStudy);
        if (extracted) {
          setSvgPlan(extracted.svg);
          setStudyClean(extracted.rest);
        } else {
          setStudyClean(rawStudy);
        }
      } else {
        setStudyClean(rawStudy);
      }
      setStudy(rawStudy);
      toast.success("تمت الدراسة بنجاح! ✅");
    } catch (err: any) {
      toast.error(err.message);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleExportDocx = async () => {
    if (!study) return;
    try {
      const catConfig = CATEGORIES.find(c => c.id === selectedCat);
      const title = `دراسة ${catConfig?.label || ""} — ${subcategory || userInput.substring(0, 40)}`;
      const res = await fetch(`${API_BASE}/api/studies/export-docx`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ text: study, title }),
      });
      if (!res.ok) throw new Error("فشل التصدير");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `HAYO-THINK-${selectedCat}-${Date.now()}.docx`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("تم تحميل الملف! 📄");
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  const handleCopy = async () => {
    if (!studyClean) return;
    await navigator.clipboard.writeText(studyClean);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success("تم نسخ الدراسة!");
  };

  const handleCopyFollowUp = async () => {
    if (!followUpA) return;
    await navigator.clipboard.writeText(followUpA);
    setFollowUpCopied(true);
    setTimeout(() => setFollowUpCopied(false), 2000);
    toast.success("تم نسخ الإجابة!");
  };

  const handleDownloadSVG = useCallback(() => {
    if (!svgPlan) return;
    const blob = new Blob([svgPlan], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `HAYO-THINK-floor-plan-${Date.now()}.svg`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("تم تحميل المخطط SVG! 📐");
  }, [svgPlan]);

  const handleDownloadPNG = useCallback(() => {
    if (!svgPlan) return;
    try {
      const parser = new DOMParser();
      const svgDoc = parser.parseFromString(svgPlan, "image/svg+xml");
      const svgEl = svgDoc.documentElement;
      const w = parseInt(svgEl.getAttribute("width") || "560");
      const h = parseInt(svgEl.getAttribute("height") || "400");
      const canvas = document.createElement("canvas");
      const scale = 2; // retina
      canvas.width = w * scale;
      canvas.height = h * scale;
      const ctx = canvas.getContext("2d")!;
      ctx.scale(scale, scale);
      const svgBlob = new Blob([svgPlan], { type: "image/svg+xml;charset=utf-8" });
      const url = URL.createObjectURL(svgBlob);
      const img = new Image();
      img.onload = () => {
        ctx.drawImage(img, 0, 0, w, h);
        URL.revokeObjectURL(url);
        canvas.toBlob(blob => {
          if (!blob) return;
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = `HAYO-THINK-floor-plan-${Date.now()}.png`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
        }, "image/png");
        toast.success("تم تحميل المخطط PNG! 🖼️");
      };
      img.onerror = () => toast.error("فشل تحويل المخطط لـ PNG");
      img.src = url;
    } catch {
      toast.error("تعذّر تحميل PNG");
    }
  }, [svgPlan]);

  const handleCopySVG = async () => {
    if (!svgPlan) return;
    await navigator.clipboard.writeText(svgPlan);
    setSvgCopied(true);
    setTimeout(() => setSvgCopied(false), 2000);
    toast.success("تم نسخ كود المخطط!");
  };

  const handleFollowUp = async () => {
    if (!followUpQ.trim() || !study) return;
    setIsFULoading(true);
    setFollowUpA(null);
    try {
      const res = await fetch(`${API_BASE}/api/studies/follow-up`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ originalStudy: study, question: followUpQ, category: selectedCat }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setFollowUpA(data.answer);
      setFollowUpQ("");
    } catch (err: any) {
      toast.error(err.message);
    } finally {
      setIsFULoading(false);
    }
  };

  const handleReset = () => {
    setSelectedCat(null);
    setSubcategory("");
    setUserInput("");
    setDetailLevel("standard");
    setStudy(null);
    setStudyClean(null);
    setSvgPlan(null);
    setModelUsed(null);
    setFollowUpA(null);
    setFollowUpQ("");
  };

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">
      {/* Top Bar */}
      <header className="h-12 bg-card border-b border-border flex items-center justify-between px-4 sticky top-0 z-10">
        <div className="flex items-center gap-3">
          <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">
            <Home className="w-4 h-4" />
          </Link>
          <div className="w-px h-5 bg-border" />
          <Brain className="w-5 h-5 text-violet-400" />
          <span className="font-bold text-sm text-white">HAYO THINK</span>
          <span className="text-[10px] bg-violet-500/20 text-violet-300 border border-violet-500/30 px-2 py-0.5 rounded-full">المستشار الاستراتيجي</span>
        </div>
        {selectedCat && !isGenerating && (
          <button onClick={handleReset} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
            <X className="w-3.5 h-3.5" /> تغيير التصنيف
          </button>
        )}
      </header>

      <div className="max-w-5xl mx-auto px-4 py-6 space-y-6">

        {/* Hero */}
        {!selectedCat && (
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
            className="text-center space-y-4 py-8">
            <div className="inline-flex items-center justify-center w-20 h-20 rounded-3xl bg-gradient-to-br from-violet-600 to-purple-600 shadow-xl shadow-violet-500/25 mb-2">
              <Brain className="w-10 h-10 text-white" />
            </div>
            <h1 className="text-4xl font-black text-white">HAYO <span className="text-violet-400">THINK</span></h1>
            <p className="text-muted-foreground max-w-xl mx-auto text-base leading-relaxed">
              صِف مشروعك في جملة واحدة — وتلقَّ دراسة احترافية متكاملة بأذكى نماذج الذكاء الاصطناعي
            </p>
            <div className="flex items-center justify-center gap-3 text-xs text-muted-foreground flex-wrap">
              <span className="flex items-center gap-1.5 bg-white/5 px-3 py-1.5 rounded-full border border-white/10">
                <Sparkles className="w-3 h-3 text-violet-400" /> Claude Opus + Gemini
              </span>
              <span className="flex items-center gap-1.5 bg-white/5 px-3 py-1.5 rounded-full border border-white/10">
                <Download className="w-3 h-3 text-blue-400" /> تصدير DOCX
              </span>
              <span className="flex items-center gap-1.5 bg-white/5 px-3 py-1.5 rounded-full border border-white/10">
                <MessageSquare className="w-3 h-3 text-emerald-400" /> سؤال متابعة
              </span>
            </div>
          </motion.div>
        )}

        {/* Category Selection */}
        {!selectedCat ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {CATEGORIES.map((cat, i) => (
              <motion.button
                key={cat.id}
                initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.08 }}
                onClick={() => setSelectedCat(cat.id)}
                className={`group relative rounded-2xl border ${cat.border} bg-card p-6 text-right hover:scale-[1.02] transition-all duration-300 hover:shadow-xl overflow-hidden`}
              >
                <div className={`absolute inset-0 bg-gradient-to-br ${cat.gradient} opacity-5 group-hover:opacity-10 transition-opacity`} />
                <div className="relative space-y-3">
                  <div className="flex items-center justify-between">
                    <div className={`w-14 h-14 rounded-2xl bg-gradient-to-br ${cat.gradient} flex items-center justify-center shadow-lg`}>
                      <cat.icon className="w-7 h-7 text-white" />
                    </div>
                    <span className="text-4xl">{cat.emoji}</span>
                  </div>
                  <div>
                    <h3 className="font-bold text-xl text-white mb-1">{cat.label}</h3>
                    <p className="text-sm text-muted-foreground leading-relaxed">{cat.desc}</p>
                  </div>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {cat.subcategories.slice(0, 3).map(sub => (
                      <span key={sub} className="text-[10px] bg-white/8 text-white/50 border border-white/10 px-2 py-0.5 rounded-full">{sub}</span>
                    ))}
                    <span className="text-[10px] text-white/30">+{cat.subcategories.length - 3}</span>
                  </div>
                </div>
              </motion.button>
            ))}
          </div>
        ) : (
          /* Input Form */
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            className="space-y-4">

            {/* Selected Category Badge */}
            <div className={`flex items-center gap-3 p-4 rounded-2xl border ${catConfig?.border ?? ""} bg-card`}>
              <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${catConfig?.gradient} flex items-center justify-center shrink-0`}>
                {catConfig && <catConfig.icon className="w-5 h-5 text-white" />}
              </div>
              <div>
                <div className="font-bold text-sm text-white">{catConfig?.label}</div>
                <div className="text-xs text-muted-foreground">{catConfig?.desc}</div>
              </div>
            </div>

            {/* Form Card */}
            <div className="bg-card border border-border rounded-2xl p-5 space-y-5">

              {/* Subcategory */}
              <div className="space-y-2">
                <label className="text-xs font-medium text-muted-foreground">التصنيف الفرعي</label>
                <div className="relative">
                  <select
                    value={subcategory}
                    onChange={e => setSubcategory(e.target.value)}
                    className="w-full bg-secondary border border-border rounded-xl px-4 py-2.5 text-sm text-foreground appearance-none cursor-pointer"
                  >
                    <option value="">— اختر تصنيفاً فرعياً (اختياري) —</option>
                    {catConfig?.subcategories.map(s => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                </div>
              </div>

              {/* Detail Level */}
              <div className="space-y-2">
                <label className="text-xs font-medium text-muted-foreground">مستوى التفصيل</label>
                <div className="flex gap-2">
                  {([["summary", "ملخص سريع", "3-5 نقاط"], ["standard", "متوسط", "5-8 صفحات"], ["detailed", "مفصّل جداً", "أقصى تفصيل"]] as const).map(([val, lbl, hint]) => (
                    <button
                      key={val}
                      onClick={() => setDetailLevel(val)}
                      className={`flex-1 py-2 rounded-xl border text-xs font-medium transition-all ${
                        detailLevel === val
                          ? "bg-violet-600 text-white border-violet-500"
                          : "bg-secondary border-border text-muted-foreground hover:bg-secondary/80"
                      }`}
                    >
                      <div>{lbl}</div>
                      <div className={`text-[10px] mt-0.5 ${detailLevel === val ? "text-violet-200" : "text-white/30"}`}>{hint}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Textarea */}
              <div className="space-y-2">
                <label className="text-xs font-medium text-muted-foreground">صِف مشروعك</label>
                <textarea
                  value={userInput}
                  onChange={e => setUserInput(e.target.value)}
                  rows={6}
                  placeholder={`مثال: ${catConfig?.examples[0] ?? "اكتب وصفاً مفصلاً لمشروعك..."}`}
                  className="w-full bg-secondary border border-border rounded-xl px-4 py-3 text-sm text-foreground placeholder:text-muted-foreground/50 resize-none focus:outline-none focus:ring-2 focus:ring-violet-500/50 leading-relaxed"
                />
                <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                  <span>كلما زدت التفاصيل، زادت دقة الدراسة</span>
                  <span>{userInput.length} حرف</span>
                </div>
              </div>

              {/* Quick Examples */}
              <div className="space-y-2">
                <label className="text-xs text-muted-foreground font-medium flex items-center gap-1.5">
                  <Info className="w-3 h-3" /> أمثلة جاهزة — اضغط للاستخدام:
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {catConfig?.examples.map((ex, i) => (
                    <button
                      key={i}
                      onClick={() => setUserInput(ex)}
                      className="text-right text-xs bg-secondary/60 hover:bg-secondary border border-border hover:border-violet-500/40 rounded-xl px-3 py-2.5 transition-all text-muted-foreground hover:text-foreground"
                    >
                      {ex}
                    </button>
                  ))}
                </div>
              </div>

              {/* Generate Button */}
              <Button
                onClick={handleGenerate}
                disabled={isGenerating || !userInput.trim()}
                size="lg"
                className="w-full gap-2 bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-700 hover:to-purple-700 text-white font-bold text-base h-13"
              >
                {isGenerating ? (
                  <><Loader2 className="w-5 h-5 animate-spin" /> جاري الإنشاء...</>
                ) : (
                  <><Brain className="w-5 h-5" /> إنشاء الدراسة</>
                )}
              </Button>
            </div>

            {/* External Tools (Engineering Only) */}
            {catConfig?.tools && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-4 space-y-3">
                <div className="flex items-center gap-2 text-sm font-semibold text-blue-300">
                  <ExternalLink className="w-4 h-4" />
                  أدوات احترافية لتصميم المخططات الهندسية
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {catConfig.tools.map(tool => (
                    <a
                      key={tool.label}
                      href={tool.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex flex-col gap-1 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-blue-500/30 rounded-xl p-3 transition-all group"
                    >
                      <span className="text-xs font-bold text-blue-300 group-hover:text-blue-200">{tool.label}</span>
                      <span className="text-[10px] text-white/40">{tool.desc}</span>
                    </a>
                  ))}
                </div>
              </motion.div>
            )}
          </motion.div>
        )}

        {/* Loading State */}
        <AnimatePresence>
          {isGenerating && (
            <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }}
              className="bg-card border border-border rounded-2xl p-8 text-center space-y-6">
              <div className="relative w-24 h-24 mx-auto">
                <div className="absolute inset-0 rounded-full bg-violet-500/20 animate-ping" />
                <div className="relative w-24 h-24 rounded-full bg-gradient-to-br from-violet-600 to-purple-600 flex items-center justify-center shadow-xl">
                  <Brain className="w-12 h-12 text-white animate-pulse" />
                </div>
              </div>
              <div>
                <motion.p
                  key={loadingMsg}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="text-base font-medium text-white"
                >
                  {loadingMsg}
                </motion.p>
                <p className="text-xs text-muted-foreground mt-2">يستخدم HAYO THINK أقوى نماذج الذكاء الاصطناعي لضمان الدقة والتفصيل</p>
              </div>
              <div className="flex justify-center gap-1.5">
                {[0, 1, 2, 3].map(i => (
                  <motion.div key={i} className="w-2 h-2 rounded-full bg-violet-500"
                    animate={{ scale: [1, 1.5, 1], opacity: [0.4, 1, 0.4] }}
                    transition={{ duration: 1.2, delay: i * 0.2, repeat: Infinity }} />
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Result */}
        <AnimatePresence>
          {studyClean && !isGenerating && (
            <motion.div ref={resultRef} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
              className="space-y-5">

              {/* Action Bar */}
              <div className="flex items-center justify-between flex-wrap gap-3 bg-card border border-border rounded-2xl px-5 py-3">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                  <span className="text-sm font-medium text-white">الدراسة جاهزة</span>
                  {modelUsed && (
                    <span className="text-[10px] bg-violet-500/15 text-violet-300 border border-violet-500/20 px-2 py-0.5 rounded-full">
                      {modelUsed}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <Button size="sm" variant="outline" onClick={handleCopy} className="gap-1.5 text-xs h-8">
                    {copied ? <CheckCircle className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? "تم النسخ" : "نسخ"}
                  </Button>
                  <Button size="sm" variant="outline" onClick={handleExportDocx} className="gap-1.5 text-xs h-8">
                    <Download className="w-3 h-3" /> تحميل DOCX
                  </Button>
                  <Button size="sm" variant="outline" onClick={handleGenerate} className="gap-1.5 text-xs h-8">
                    <RefreshCw className="w-3 h-3" /> إعادة إنشاء
                  </Button>
                </div>
              </div>

              {/* SVG Floor Plan (Engineering) */}
              {svgPlan && (
                <div className="bg-card border border-blue-500/25 rounded-2xl overflow-hidden">
                  {/* Floor Plan Header */}
                  <div className="flex items-center justify-between px-5 py-3 border-b border-border flex-wrap gap-2">
                    <div className="flex items-center gap-2 text-sm font-bold text-blue-300">
                      <Building2 className="w-4 h-4" /> {selectedCat === "engineering" ? "المخطط الهندسي المقترح" : selectedCat === "medical" ? "مخطط المنشأة الصحية" : selectedCat === "tech" ? "مخطط البنية المعمارية" : selectedCat === "agriculture" ? "مخطط تنظيم المزرعة" : "المخطط البصري"}
                      <span className="text-[10px] font-normal text-blue-400/70 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded-full">مُنشأ بالذكاء الاصطناعي</span>
                    </div>
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {/* Download SVG */}
                      <button
                        onClick={handleDownloadSVG}
                        className="flex items-center gap-1 text-[11px] font-medium text-blue-300 hover:text-blue-200 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 hover:border-blue-500/40 px-2.5 py-1 rounded-lg transition-all"
                        title="تحميل المخطط بصيغة SVG (قابل للتعديل)"
                      >
                        <FileCode2 className="w-3 h-3" /> SVG
                      </button>
                      {/* Download PNG */}
                      <button
                        onClick={handleDownloadPNG}
                        className="flex items-center gap-1 text-[11px] font-medium text-cyan-300 hover:text-cyan-200 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20 hover:border-cyan-500/40 px-2.5 py-1 rounded-lg transition-all"
                        title="تحميل المخطط بصيغة PNG"
                      >
                        <ImageDown className="w-3 h-3" /> PNG
                      </button>
                      {/* Copy SVG Code */}
                      <button
                        onClick={handleCopySVG}
                        className="flex items-center gap-1 text-[11px] font-medium text-white/50 hover:text-white/80 bg-white/5 hover:bg-white/10 border border-white/10 px-2.5 py-1 rounded-lg transition-all"
                        title="نسخ كود SVG"
                      >
                        {svgCopied ? <CheckCircle className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        {svgCopied ? "تم" : "نسخ"}
                      </button>
                      <div className="w-px h-4 bg-white/10" />
                      <button
                        onClick={() => setShowFloorPlan(!showFloorPlan)}
                        className="text-[11px] text-muted-foreground hover:text-foreground transition-colors px-1"
                      >
                        {showFloorPlan ? "إخفاء" : "إظهار"}
                      </button>
                    </div>
                  </div>

                  <AnimatePresence>
                    {showFloorPlan && (
                      <motion.div
                        initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }}
                        className="overflow-hidden"
                      >
                        <div className="p-4 bg-slate-900 flex justify-center" ref={floorPlanRef}>
                          <div
                            className="w-full max-w-2xl overflow-x-auto rounded-xl"
                            dangerouslySetInnerHTML={{ __html: svgPlan }}
                          />
                        </div>
                        {/* Bottom: download actions + tools links */}
                        <div className="border-t border-border px-5 py-3 space-y-2">
                          <div className="flex items-center justify-between flex-wrap gap-2">
                            <p className="text-[10px] text-white/30">مخطط تقريبي — للتعديل وإضافة التفاصيل استخدم أحد الأدوات أدناه</p>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={handleDownloadSVG}
                                className="flex items-center gap-1.5 text-xs text-blue-300 hover:text-blue-200 transition-colors"
                              >
                                <Download className="w-3 h-3" /> تحميل SVG
                              </button>
                              <span className="text-white/20">|</span>
                              <button
                                onClick={handleDownloadPNG}
                                className="flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200 transition-colors"
                              >
                                <FileImage className="w-3 h-3" /> تحميل PNG
                              </button>
                            </div>
                          </div>
                          {/* Professional Tools to refine the plan */}
                          <div className="flex items-center gap-2 flex-wrap pt-1">
                            <span className="text-[10px] text-white/40 shrink-0">صمّم وعدّل باستخدام:</span>
                            {catConfig?.tools?.map(tool => (
                              <a
                                key={tool.label}
                                href={tool.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 bg-blue-500/8 hover:bg-blue-500/15 border border-blue-500/15 px-2 py-0.5 rounded-lg transition-all"
                              >
                                {tool.label} <ExternalLink className="w-2.5 h-2.5" />
                              </a>
                            ))}
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              )}

              {/* Study Content */}
              <div className="bg-card border border-border rounded-2xl overflow-hidden">
                {/* Content Header with Copy */}
                <div className="flex items-center justify-between px-6 py-3 border-b border-border">
                  <span className="text-xs font-medium text-muted-foreground">نص الدراسة</span>
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground hover:text-foreground bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 px-2.5 py-1 rounded-lg transition-all"
                  >
                    {copied ? <CheckCircle className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? "تم النسخ ✓" : "نسخ الدراسة"}
                  </button>
                </div>
                <div className="p-6 md:p-8">
                  <StudyMarkdown content={studyClean} />
                </div>
                {/* Content Footer with Copy */}
                <div className="flex items-center justify-end px-6 pb-4">
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1.5 text-[11px] text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {copied ? <CheckCircle className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? "تم النسخ" : "نسخ النص كاملاً"}
                  </button>
                </div>
              </div>

              {/* Engineering External Tools (after result) */}
              {catConfig?.tools && (
                <div className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-4 space-y-3">
                  <div className="text-sm font-semibold text-blue-300 flex items-center gap-2">
                    <ExternalLink className="w-4 h-4" />
                    أنشئ مخططاً تفاعلياً باستخدام:
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {catConfig.tools.map(tool => (
                      <a key={tool.label} href={tool.url} target="_blank" rel="noopener noreferrer"
                        className="flex flex-col gap-1 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-blue-500/40 rounded-xl p-3 transition-all group">
                        <span className="text-xs font-bold text-blue-300 flex items-center gap-1">
                          {tool.label} <ExternalLink className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
                        </span>
                        <span className="text-[10px] text-white/40">{tool.desc}</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Follow-up Section */}
              <div className="bg-card border border-border rounded-2xl p-5 space-y-4">
                <div className="flex items-center gap-2 text-sm font-bold text-white">
                  <MessageSquare className="w-4 h-4 text-violet-400" />
                  سؤال متابعة
                </div>
                <div className="flex gap-2">
                  <input
                    value={followUpQ}
                    onChange={e => setFollowUpQ(e.target.value)}
                    onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleFollowUp(); } }}
                    placeholder="مثال: ما تكلفة التشطيب الفاخر بدل المتوسط؟"
                    className="flex-1 bg-secondary border border-border rounded-xl px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-violet-500/50"
                  />
                  <Button onClick={handleFollowUp} disabled={isFULoading || !followUpQ.trim()} size="sm" className="gap-1.5 bg-violet-600 hover:bg-violet-700 shrink-0">
                    {isFULoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                  </Button>
                </div>

                <AnimatePresence>
                  {isFULoading && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                      className="flex items-center gap-3 text-sm text-muted-foreground">
                      <Loader2 className="w-4 h-4 animate-spin text-violet-400" />
                      جاري الإجابة...
                    </motion.div>
                  )}
                  {followUpA && (
                    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
                      className="bg-secondary/50 border border-violet-500/20 rounded-xl overflow-hidden">
                      {/* Follow-up header */}
                      <div className="flex items-center justify-between px-4 py-2 border-b border-violet-500/15">
                        <span className="text-[11px] text-violet-400 font-medium flex items-center gap-1.5">
                          <CheckCircle className="w-3 h-3" /> الإجابة
                        </span>
                        <button
                          onClick={handleCopyFollowUp}
                          className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground bg-white/5 hover:bg-white/10 border border-white/10 px-2 py-0.5 rounded-lg transition-all"
                        >
                          {followUpCopied ? <CheckCircle className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          {followUpCopied ? "تم" : "نسخ"}
                        </button>
                      </div>
                      <div className="p-4">
                        <StudyMarkdown content={followUpA} />
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

            </motion.div>
          )}
        </AnimatePresence>

      </div>
    </div>
  );
}
