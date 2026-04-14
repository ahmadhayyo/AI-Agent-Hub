/**
 * HAYO AI — Office Suite (Professional Edition)
 * 6 tabs: File Converter | PowerPoint AI | Word Reports | Excel Editor | AI Tools | OCR
 */
import { useState, useCallback, useRef, useEffect } from "react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  Home, Loader2, Upload, Download, FileText, Presentation,
  Table, Wand2, ScanText, CheckCircle2, X,
  RefreshCw, Briefcase, Languages, SpellCheck, Mail,
  ClipboardList, FileSignature, Copy, Sparkles, ArrowLeft,
  ChevronRight,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";

const API_BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

// ─── Helper: download blob ────────────────────────────────────────────────────
function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Supported conversions map ───────────────────────────────────────────────
const CONVERSIONS: Record<string, string[]> = {
  pdf:  ["txt", "docx", "xlsx", "csv"],
  docx: ["txt", "html", "pdf", "xlsx", "csv", "md"],
  doc:  ["txt", "pdf", "docx"],
  xlsx: ["csv", "json", "txt", "pdf", "docx", "html"],
  xls:  ["csv", "xlsx", "json", "pdf", "docx"],
  csv:  ["xlsx", "json", "pdf", "docx", "txt", "html"],
  json: ["csv", "xlsx", "txt", "pdf", "html"],
  txt:  ["pdf", "docx", "html", "md"],
  md:   ["html", "pdf", "docx", "txt"],
  html: ["txt", "pdf", "docx", "md"],
  png:  ["pdf", "jpg"],
  jpg:  ["pdf", "png"],
  jpeg: ["pdf", "png"],
  gif:  ["pdf"],
  webp: ["pdf", "jpg"],
  pptx: ["txt"],
};

const FORMAT_LABELS: Record<string, string> = {
  pdf: "PDF", txt: "نص (.txt)", docx: "Word (.docx)", html: "HTML",
  xlsx: "Excel (.xlsx)", csv: "CSV", json: "JSON", md: "Markdown",
  png: "PNG", jpg: "JPEG", jpeg: "JPEG", gif: "GIF", webp: "WebP",
  pptx: "PowerPoint (.pptx)",
};

const FORMAT_ICONS: Record<string, string> = {
  pdf: "📄", txt: "📝", docx: "📘", html: "🌐", xlsx: "📊",
  csv: "📋", json: "🔧", md: "✍️", png: "🖼️", jpg: "🖼️",
  jpeg: "🖼️", gif: "🎞️", webp: "🌅", pptx: "📊",
};

// ─── Section Header Component ─────────────────────────────────────────────────
function SectionHeader({ icon: Icon, title, desc, gradient }: {
  icon: any; title: string; desc: string; gradient: string;
}) {
  return (
    <div className={`rounded-2xl p-5 mb-6 bg-gradient-to-r ${gradient} border border-white/5`}>
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 rounded-xl bg-white/10 flex items-center justify-center shrink-0 backdrop-blur-sm">
          <Icon className="w-6 h-6 text-white" />
        </div>
        <div>
          <h2 className="font-bold text-lg text-white">{title}</h2>
          <p className="text-sm text-white/70 mt-0.5 leading-relaxed">{desc}</p>
        </div>
      </div>
    </div>
  );
}

// ─── TAB 1: File Converter ────────────────────────────────────────────────────
function FileConverterTab() {
  const [file, setFile] = useState<File | null>(null);
  const [toFormat, setToFormat] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<{ from: string; to: string; name: string }[]>([]);
  const dropRef = useRef<HTMLDivElement>(null);

  const fromExt = file ? file.name.split(".").pop()?.toLowerCase() || "" : "";
  const targets = fromExt ? (CONVERSIONS[fromExt] || []) : [];

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) { setFile(f); setToFormat(""); }
  }, []);

  const onFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) { setFile(f); setToFormat(""); }
  };

  const handleConvert = async () => {
    if (!file || !toFormat) return;
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("toFormat", toFormat);
      const res = await fetch(`${API_BASE}/api/office/convert`, { method: "POST", body: fd, credentials: "include" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as any).error || "فشل التحويل");
      }
      const blob = await res.blob();
      const name = file.name.replace(/\.[^.]+$/, "") + "." + toFormat;
      downloadBlob(blob, name);
      setHistory(h => [{ from: fromExt, to: toFormat, name: file.name }, ...h].slice(0, 10));
      toast.success("تم التحويل بنجاح! 🎉");
    } catch (err: any) {
      toast.error(err.message || "حدث خطأ أثناء التحويل");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        icon={RefreshCw}
        title="محوّل الملفات الاحترافي"
        desc="حوّل ملفاتك بين أكثر من 30 صيغة مختلفة بنقرة واحدة — PDF، Word، Excel، CSV، JSON، HTML، والمزيد"
        gradient="from-indigo-600/80 to-violet-700/80"
      />

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Drop Zone */}
        <div
          ref={dropRef}
          onDragOver={e => e.preventDefault()}
          onDrop={onDrop}
          className="relative border-2 border-dashed border-border hover:border-primary/60 rounded-2xl p-10 text-center transition-all cursor-pointer group bg-secondary/20 hover:bg-secondary/40"
          onClick={() => document.getElementById("file-input")?.click()}
        >
          <input id="file-input" type="file" className="hidden" onChange={onFileInput}
            accept=".pdf,.docx,.doc,.xlsx,.xls,.csv,.json,.txt,.md,.html,.png,.jpg,.jpeg,.gif,.webp,.pptx" />
          <div className="flex flex-col items-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center group-hover:bg-primary/20 transition-colors group-hover:scale-110 duration-300">
              <Upload className="w-8 h-8 text-primary" />
            </div>
            {file ? (
              <div className="space-y-1">
                <div className="inline-flex items-center gap-2 px-3 py-1 bg-primary/10 rounded-full text-primary text-sm font-mono font-bold">
                  {FORMAT_ICONS[fromExt] || "📄"} {fromExt.toUpperCase()}
                </div>
                <p className="font-semibold text-foreground">{file.name}</p>
                <p className="text-sm text-muted-foreground">{(file.size / 1024).toFixed(1)} KB</p>
              </div>
            ) : (
              <div className="space-y-2">
                <p className="font-semibold text-foreground text-lg">اسحب الملف هنا أو اضغط للاختيار</p>
                <p className="text-sm text-muted-foreground">PDF · Word · Excel · CSV · JSON · TXT · HTML · PNG · JPG · PPTX</p>
                <p className="text-xs text-muted-foreground/60 mt-1">الحد الأقصى: 50 MB</p>
              </div>
            )}
          </div>
          {file && (
            <button
              onClick={e => { e.stopPropagation(); setFile(null); setToFormat(""); }}
              className="absolute top-3 right-3 p-1.5 rounded-full hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Conversion Options */}
        <div className="space-y-5">
          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">الصيغة الحالية</label>
            <div className="flex items-center gap-3 px-4 py-3 bg-secondary/50 rounded-xl border border-border">
              <FileText className="w-4 h-4 text-primary" />
              <span className="font-mono font-bold text-primary">{fromExt ? fromExt.toUpperCase() : "—"}</span>
              {file && <span className="text-sm text-muted-foreground truncate">{file.name}</span>}
            </div>
          </div>

          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">
              تحويل إلى {targets.length > 0 && <span className="text-primary/70 text-xs">({targets.length} صيغة متاحة)</span>}
            </label>
            {targets.length > 0 ? (
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {targets.map(ext => (
                  <button
                    key={ext}
                    onClick={() => setToFormat(ext)}
                    className={`px-3 py-2.5 rounded-xl border text-sm font-medium transition-all flex items-center gap-2 ${
                      toFormat === ext
                        ? "border-primary bg-primary/10 text-primary shadow-sm shadow-primary/20 scale-105"
                        : "border-border hover:border-primary/40 text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                    }`}
                  >
                    <span className="text-base leading-none">{FORMAT_ICONS[ext] || "📄"}</span>
                    <span className="truncate">{FORMAT_LABELS[ext] || ext.toUpperCase()}</span>
                    {toFormat === ext && <CheckCircle2 className="w-3.5 h-3.5 text-primary mr-auto shrink-0" />}
                  </button>
                ))}
              </div>
            ) : (
              <div className="px-4 py-6 bg-secondary/30 rounded-xl border border-dashed border-border text-center">
                <RefreshCw className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">
                  {file ? "لا توجد تحويلات متاحة لهذه الصيغة" : "اختر ملفاً أولاً لعرض صيغ التحويل المتاحة"}
                </p>
              </div>
            )}
          </div>

          <Button
            onClick={handleConvert}
            disabled={!file || !toFormat || loading}
            className="w-full h-12 text-base bg-gradient-to-r from-indigo-500 to-violet-600 hover:from-indigo-600 hover:to-violet-700 shadow-lg shadow-indigo-500/20"
          >
            {loading
              ? <><Loader2 className="w-4 h-4 animate-spin ml-2" />جارٍ التحويل...</>
              : <><RefreshCw className="w-4 h-4 ml-2" />تحويل الآن {toFormat && `← ${toFormat.toUpperCase()}`}</>}
          </Button>
        </div>
      </div>

      {/* History */}
      {history.length > 0 && (
        <div className="bg-secondary/30 rounded-xl border border-border p-4">
          <h3 className="text-sm font-semibold mb-3 text-muted-foreground flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" /> آخر التحويلات
          </h3>
          <div className="space-y-2">
            {history.map((h, i) => (
              <div key={i} className="flex items-center gap-2 text-sm bg-secondary/40 rounded-lg px-3 py-2">
                <span>{FORMAT_ICONS[h.from] || "📄"}</span>
                <span className="text-foreground truncate flex-1">{h.name}</span>
                <span className="text-muted-foreground shrink-0 flex items-center gap-1">
                  <span className="font-mono text-xs">{h.from.toUpperCase()}</span>
                  <ChevronRight className="w-3 h-3" />
                  <span className="font-mono text-xs text-emerald-400">{h.to.toUpperCase()}</span>
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── TAB 2: PowerPoint Generator ─────────────────────────────────────────────
function PowerPointTab() {
  const [topic, setTopic] = useState("");
  const [details, setDetails] = useState("");
  const [slideCount, setSlideCount] = useState(10);
  const [style, setStyle] = useState<"professional" | "creative" | "academic">("professional");
  const [language, setLanguage] = useState("ar");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMsg, setStatusMsg] = useState("");
  const [preview, setPreview] = useState<{ topic: string; slides: number } | null>(null);

  useEffect(() => {
    if (!loading) { setProgress(0); setStatusMsg(""); return; }
    const stages = [
      { pct: 5,  msg: "جارٍ تحليل الموضوع وإنشاء هيكل العرض...", delay: 500 },
      { pct: 20, msg: "يُصمّم الذكاء الاصطناعي محتوى الشرائح...", delay: 8000 },
      { pct: 40, msg: "إضافة الرسوم البيانية والجداول...", delay: 18000 },
      { pct: 60, msg: "تنسيق الألوان والخطوط والتصميم...", delay: 28000 },
      { pct: 80, msg: "إنشاء ملف PowerPoint النهائي...", delay: 38000 },
      { pct: 92, msg: "اللمسات الأخيرة، تقريباً انتهى...", delay: 46000 },
    ];
    const timers: ReturnType<typeof setTimeout>[] = [];
    stages.forEach(({ pct, msg, delay }) => {
      timers.push(setTimeout(() => { setProgress(pct); setStatusMsg(msg); }, delay));
    });
    return () => timers.forEach(clearTimeout);
  }, [loading]);

  const handleGenerate = async () => {
    if (!topic.trim()) { toast.error("يرجى إدخال موضوع العرض"); return; }
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/office/generate-pptx`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ topic, details, slideCount, style, language }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as any).error || "فشل إنشاء العرض");
      }
      const blob = await res.blob();
      const filename = `${topic.slice(0, 30)}.pptx`;
      downloadBlob(blob, filename);
      setPreview({ topic, slides: slideCount });
      toast.success("تم إنشاء العرض وتحميله! 🎉");
    } catch (err: any) {
      toast.error(err.message || "حدث خطأ");
    } finally {
      setLoading(false);
    }
  };

  const styleOptions = [
    { id: "professional", label: "رسمي", desc: "خلفية داكنة أنيقة", color: "from-indigo-500 to-blue-600", emoji: "💼" },
    { id: "creative",     label: "إبداعي", desc: "ألوان ذهبية جذابة", color: "from-amber-500 to-orange-500", emoji: "✨" },
    { id: "academic",     label: "أكاديمي", desc: "تصميم علمي منظم", color: "from-blue-500 to-cyan-500", emoji: "🎓" },
  ];

  return (
    <div className="space-y-6">
      <SectionHeader
        icon={Presentation}
        title="إنشاء عروض PowerPoint بالذكاء الاصطناعي"
        desc="أدخل موضوعك واضغط إنشاء — سيبني الذكاء الاصطناعي عرضاً تقديمياً احترافياً جاهزاً للتحميل في ثوانٍ"
        gradient="from-violet-600/80 to-indigo-700/80"
      />

      <div className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-5">
          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">موضوع العرض التقديمي <span className="text-destructive">*</span></label>
            <textarea
              value={topic}
              onChange={e => setTopic(e.target.value)}
              rows={2}
              dir="auto"
              placeholder="مثال: استراتيجية التسويق الرقمي للشركات الصغيرة في 2025..."
              className="w-full px-4 py-3 bg-secondary/50 border border-border rounded-xl text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 placeholder:text-muted-foreground/50 transition-all"
            />
            <p className="text-xs text-muted-foreground/50 mt-1 text-left">{topic.length} / 200 حرف</p>
          </div>

          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">
              تفاصيل وملاحظات إضافية <span className="text-muted-foreground/50 text-xs">(اختياري)</span>
            </label>
            <textarea
              value={details}
              onChange={e => setDetails(e.target.value)}
              rows={3}
              dir="auto"
              placeholder="أضف بيانات محددة، إحصاءات، نقاط يجب تغطيتها، جمهور مستهدف، أو أي توجيهات خاصة..."
              className="w-full px-4 py-3 bg-secondary/50 border border-border rounded-xl text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 placeholder:text-muted-foreground/50 transition-all"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium text-muted-foreground block mb-2">
                عدد الشرائح: <span className="text-primary font-bold">{slideCount}</span>
              </label>
              <input
                type="range" min={5} max={20} value={slideCount}
                onChange={e => setSlideCount(Number(e.target.value))}
                className="w-full accent-primary"
              />
              <div className="flex justify-between text-xs text-muted-foreground/50 mt-1">
                <span>5</span><span>20</span>
              </div>
            </div>
            <div>
              <label className="text-sm font-medium text-muted-foreground block mb-2">لغة العرض</label>
              <div className="flex gap-2">
                {[{ id: "ar", label: "🇸🇦 عربي" }, { id: "en", label: "🇺🇸 English" }].map(l => (
                  <button key={l.id} onClick={() => setLanguage(l.id)}
                    className={`flex-1 px-3 py-2.5 rounded-xl text-sm border transition-all ${language === l.id ? "border-primary bg-primary/10 text-primary font-medium" : "border-border text-muted-foreground hover:border-primary/40"}`}>
                    {l.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">نمط التصميم</label>
            <div className="grid grid-cols-3 gap-3">
              {styleOptions.map(s => (
                <button key={s.id} onClick={() => setStyle(s.id as any)}
                  className={`p-4 rounded-xl border text-right transition-all ${style === s.id ? "border-primary bg-primary/10 shadow-sm" : "border-border hover:border-primary/40 hover:bg-secondary/50"}`}>
                  <div className={`w-10 h-1.5 rounded-full bg-gradient-to-r ${s.color} mb-3`} />
                  <p className="text-sm font-semibold">{s.emoji} {s.label}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{s.desc}</p>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="bg-gradient-to-b from-indigo-900/30 to-violet-900/20 border border-indigo-500/20 rounded-2xl p-5">
            <Presentation className="w-10 h-10 text-indigo-400 mb-3" />
            <h3 className="font-bold mb-2">ماذا ستحصل؟</h3>
            <div className="space-y-2.5 text-sm">
              {[
                "محتوى احترافي مكتوب بالذكاء الاصطناعي",
                `${slideCount} شريحة منظمة ومنسقة`,
                "ملاحظات المتحدث لكل شريحة",
                "رسوم بيانية وجداول بيانات",
                "جاهز للتعديل في PowerPoint",
              ].map(f => (
                <div key={f} className="flex items-start gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span className="text-muted-foreground">{f}</span>
                </div>
              ))}
            </div>
          </div>

          {preview && (
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <p className="font-medium text-emerald-300 text-sm">آخر عرض تم إنشاؤه</p>
              </div>
              <p className="text-sm text-foreground font-medium truncate">{preview.topic}</p>
              <p className="text-xs text-muted-foreground mt-1">{preview.slides} شريحة • تم التحميل بنجاح</p>
            </div>
          )}
        </div>
      </div>

      {loading && (
        <div className="space-y-3 bg-indigo-950/40 border border-indigo-500/20 rounded-xl p-5">
          <div className="flex items-center justify-between text-sm">
            <span className="text-indigo-300 font-medium flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" />
              {statusMsg || "جارٍ الإعداد..."}
            </span>
            <span className="font-mono text-indigo-400 font-bold text-lg">{progress}%</span>
          </div>
          <div className="w-full bg-secondary/50 rounded-full h-3 overflow-hidden">
            <div
              className="h-3 rounded-full bg-gradient-to-r from-indigo-500 to-violet-500 transition-all duration-1000"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="text-xs text-muted-foreground/60">قد يستغرق إنشاء العرض حتى 60 ثانية لضمان الجودة الاحترافية</p>
        </div>
      )}

      <Button onClick={handleGenerate} disabled={!topic.trim() || loading}
        className="w-full h-12 text-base bg-gradient-to-r from-indigo-500 to-violet-600 hover:from-indigo-600 hover:to-violet-700 shadow-lg shadow-indigo-500/20">
        {loading
          ? <><Loader2 className="w-4 h-4 animate-spin ml-2" />يعمل الذكاء الاصطناعي على إنشاء {slideCount} شريحة...</>
          : <><Presentation className="w-4 h-4 ml-2" />إنشاء العرض التقديمي بالذكاء الاصطناعي</>}
      </Button>
    </div>
  );
}

// ─── TAB 3: Word Report Generator ────────────────────────────────────────────
function WordReportTab() {
  const [topic, setTopic] = useState("");
  const [details, setDetails] = useState("");
  const [type, setType] = useState<"business" | "academic" | "technical">("business");
  const [language, setLanguage] = useState("ar");
  const [pageCount, setPageCount] = useState(5);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMsg, setStatusMsg] = useState("");

  useEffect(() => {
    if (!loading) { setProgress(0); setStatusMsg(""); return; }
    const stages = [
      { pct: 8,  msg: "تحليل الموضوع وهيكلة التقرير...", delay: 500 },
      { pct: 30, msg: "كتابة محتوى التقرير بالذكاء الاصطناعي...", delay: 7000 },
      { pct: 60, msg: "إضافة الإحصاءات والبيانات والتحليلات...", delay: 18000 },
      { pct: 85, msg: "تنسيق ملف Word النهائي...", delay: 27000 },
      { pct: 94, msg: "المراجعة الأخيرة والتدقيق...", delay: 32000 },
    ];
    const timers: ReturnType<typeof setTimeout>[] = [];
    stages.forEach(({ pct, msg, delay }) => {
      timers.push(setTimeout(() => { setProgress(pct); setStatusMsg(msg); }, delay));
    });
    return () => timers.forEach(clearTimeout);
  }, [loading]);

  const handleGenerate = async () => {
    if (!topic.trim()) { toast.error("يرجى إدخال موضوع التقرير"); return; }
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/office/generate-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ topic, details, type, language, pageCount }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as any).error || "فشل إنشاء التقرير");
      }
      const blob = await res.blob();
      downloadBlob(blob, `تقرير-${topic.slice(0, 20)}.docx`);
      toast.success("تم إنشاء التقرير وتحميله! 📄");
    } catch (err: any) {
      toast.error(err.message || "حدث خطأ");
    } finally {
      setLoading(false);
    }
  };

  const typeOptions = [
    { id: "business", label: "تجاري", icon: "💼", desc: "تقارير الأعمال والمبيعات والتسويق" },
    { id: "academic", label: "أكاديمي", icon: "🎓", desc: "أبحاث ودراسات ومقالات علمية" },
    { id: "technical", label: "تقني", icon: "⚙️", desc: "وثائق فنية ومواصفات تقنية" },
  ];

  return (
    <div className="space-y-6">
      <SectionHeader
        icon={FileText}
        title="إنشاء تقارير Word احترافية"
        desc="اكتب موضوعك وسيُنشئ الذكاء الاصطناعي تقريراً Word كاملاً ومنسقاً — مقدمة، تحليل، نتائج، وتوصيات"
        gradient="from-blue-600/80 to-indigo-700/80"
      />

      <div className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-5">
          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">موضوع التقرير <span className="text-destructive">*</span></label>
            <textarea
              value={topic}
              onChange={e => setTopic(e.target.value)}
              rows={2}
              dir="auto"
              placeholder="مثال: تحليل أداء المبيعات للربع الأول 2025، دراسة جدوى مشروع..."
              className="w-full px-4 py-3 bg-secondary/50 border border-border rounded-xl text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 placeholder:text-muted-foreground/50 transition-all"
            />
          </div>

          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">
              بيانات وملاحظات إضافية <span className="text-muted-foreground/50 text-xs">(اختياري)</span>
            </label>
            <textarea
              value={details}
              onChange={e => setDetails(e.target.value)}
              rows={3}
              dir="auto"
              placeholder="أضف أرقاماً، إحصاءات، نتائج، بيانات محددة، أو أي معلومات تريد تضمينها في التقرير..."
              className="w-full px-4 py-3 bg-secondary/50 border border-border rounded-xl text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50 placeholder:text-muted-foreground/50 transition-all"
            />
          </div>

          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">نوع التقرير</label>
            <div className="grid grid-cols-3 gap-3">
              {typeOptions.map(t => (
                <button key={t.id} onClick={() => setType(t.id as any)}
                  className={`p-4 rounded-xl border text-right transition-all ${type === t.id ? "border-primary bg-primary/10 shadow-sm" : "border-border hover:border-primary/40 hover:bg-secondary/50"}`}>
                  <span className="text-2xl block mb-2">{t.icon}</span>
                  <p className="text-sm font-semibold">{t.label}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{t.desc}</p>
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium text-muted-foreground block mb-2">لغة التقرير</label>
              <div className="flex gap-2">
                {[{ id: "ar", label: "🇸🇦 عربي" }, { id: "en", label: "🇺🇸 English" }].map(l => (
                  <button key={l.id} onClick={() => setLanguage(l.id)}
                    className={`flex-1 px-3 py-2.5 rounded-xl text-sm border transition-all ${language === l.id ? "border-primary bg-primary/10 text-primary font-medium" : "border-border text-muted-foreground hover:border-primary/40"}`}>
                    {l.label}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="text-sm font-medium text-muted-foreground block mb-2">
                عدد الصفحات: <span className="text-primary font-bold">{pageCount}</span>
              </label>
              <input type="range" min={2} max={20} value={pageCount}
                onChange={e => setPageCount(Number(e.target.value))}
                className="w-full accent-primary mt-2" />
              <div className="flex justify-between text-xs text-muted-foreground/50 mt-1">
                <span>2</span><span>20</span>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-gradient-to-b from-blue-900/30 to-indigo-900/20 border border-blue-500/20 rounded-2xl p-5">
          <FileText className="w-10 h-10 text-blue-400 mb-3" />
          <h3 className="font-bold mb-2">مكونات التقرير</h3>
          <div className="space-y-2.5 text-sm">
            {[
              "صفحة غلاف احترافية",
              "فهرس المحتويات",
              "مقدمة وخلفية الموضوع",
              "تحليل مفصّل ودقيق",
              "جداول وإحصاءات",
              "خلاصة وتوصيات",
            ].map(f => (
              <div key={f} className="flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                <span className="text-muted-foreground">{f}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {loading && (
        <div className="space-y-3 bg-blue-950/40 border border-blue-500/20 rounded-xl p-5">
          <div className="flex items-center justify-between text-sm">
            <span className="text-blue-300 font-medium flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" />
              {statusMsg || "جارٍ الإعداد..."}
            </span>
            <span className="font-mono text-blue-400 font-bold text-lg">{progress}%</span>
          </div>
          <div className="w-full bg-secondary/50 rounded-full h-3 overflow-hidden">
            <div
              className="h-3 rounded-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-1000"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="text-xs text-muted-foreground/60">يستغرق إنشاء التقرير 30-45 ثانية للحصول على محتوى احترافي متكامل</p>
        </div>
      )}

      <Button onClick={handleGenerate} disabled={!topic.trim() || loading}
        className="w-full h-12 text-base bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 shadow-lg shadow-blue-500/20">
        {loading
          ? <><Loader2 className="w-4 h-4 animate-spin ml-2" />يكتب الذكاء الاصطناعي التقرير...</>
          : <><FileText className="w-4 h-4 ml-2" />إنشاء التقرير بالذكاء الاصطناعي</>}
      </Button>
    </div>
  );
}

// ─── TAB 4: Excel Editor (AI-powered) ────────────────────────────────────────
function ExcelTab() {
  const [file, setFile] = useState<File | null>(null);
  const [instruction, setInstruction] = useState("");
  const [result, setResult] = useState<{ headers: string[]; rows: any[][]; summary: string; xlsxBase64?: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState("");

  const handleProcess = async () => {
    if (!file || !instruction.trim()) { toast.error("يرجى اختيار ملف وإدخال التعليمات"); return; }
    setLoading(true);
    setResult(null);
    try {
      setStep("جارٍ رفع الملف وتحليل البيانات بالذكاء الاصطناعي...");
      const fd = new FormData();
      fd.append("file", file);
      fd.append("instruction", instruction);
      const res = await fetch(`${API_BASE}/api/office/process-excel`, { method: "POST", body: fd, credentials: "include" });
      setStep("جارٍ معالجة النتيجة...");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "فشلت المعالجة");
      if (!data.headers || !data.rows) throw new Error("تنسيق البيانات المُعادة غير صحيح");
      setResult({ headers: data.headers, rows: data.rows, summary: data.summary || "تمت المعالجة بنجاح", xlsxBase64: data.xlsxBase64 });
      toast.success(data.summary || "تمت المعالجة بنجاح 🎉");
    } catch (err: any) {
      toast.error(err.message || "فشلت عملية المعالجة");
    } finally {
      setLoading(false);
      setStep("");
    }
  };

  const handleDownload = () => {
    if (!result?.xlsxBase64) return;
    const bytes = Uint8Array.from(atob(result.xlsxBase64), c => c.charCodeAt(0));
    const blob = new Blob([bytes], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
    const filename = file ? file.name.replace(/\.[^.]+$/, "-processed.xlsx") : "processed.xlsx";
    downloadBlob(blob, filename);
    toast.success("تم تحميل الملف!");
  };

  const suggestions = [
    "احسب مجموع كل عمود رقمي",
    "أضف عمود النسبة المئوية",
    "رتب البيانات تنازلياً حسب أول عمود",
    "أزل الصفوف الفارغة",
    "احسب المتوسط والوسيط لكل عمود",
    "أضف عمود التصنيف (ممتاز/جيد/ضعيف)",
  ];

  return (
    <div className="space-y-6">
      <SectionHeader
        icon={Table}
        title="معالجة Excel بالذكاء الاصطناعي"
        desc="ارفع ملف Excel أو CSV واطلب تعديلات بالكلام العادي — حسابات، ترتيب، تحليل، وتصدير فوري"
        gradient="from-emerald-600/80 to-teal-700/80"
      />

      <div className="grid lg:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">ملف Excel أو CSV</label>
            <label className="flex items-center gap-3 p-4 bg-secondary/50 border border-dashed border-border rounded-xl cursor-pointer hover:border-emerald-500/50 hover:bg-secondary/70 transition-all group">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 flex items-center justify-center group-hover:bg-emerald-500/20 transition-colors">
                <Table className="w-5 h-5 text-emerald-400" />
              </div>
              <div className="flex-1 min-w-0">
                {file ? (
                  <>
                    <p className="font-medium text-sm truncate text-foreground">{file.name}</p>
                    <p className="text-xs text-emerald-400">{(file.size / 1024).toFixed(1)} KB • تم الاختيار</p>
                  </>
                ) : (
                  <>
                    <p className="text-sm font-medium text-muted-foreground">اختر ملف Excel أو CSV</p>
                    <p className="text-xs text-muted-foreground/60 mt-0.5">يدعم: .xlsx, .xls, .csv</p>
                  </>
                )}
              </div>
              {file && <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />}
              <input type="file" accept=".xlsx,.xls,.csv" className="hidden"
                onChange={e => { setFile(e.target.files?.[0] || null); setResult(null); }} />
            </label>
          </div>

          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">تعليمات المعالجة</label>
            <textarea
              value={instruction}
              onChange={e => setInstruction(e.target.value)}
              rows={4}
              dir="auto"
              placeholder="مثال: احسب مجموع العمود B وأضف عمود النسبة المئوية..."
              className="w-full px-4 py-3 bg-secondary/50 border border-border rounded-xl text-sm resize-none focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500/50 placeholder:text-muted-foreground/50 transition-all"
            />
          </div>

          <div>
            <p className="text-xs text-muted-foreground mb-2 font-medium">اقتراحات سريعة:</p>
            <div className="flex flex-wrap gap-2">
              {suggestions.map(s => (
                <button key={s} onClick={() => setInstruction(s)}
                  className="px-3 py-1.5 bg-secondary/50 border border-border rounded-full text-xs hover:border-emerald-500/40 hover:text-emerald-400 hover:bg-emerald-500/5 transition-all">
                  {s}
                </button>
              ))}
            </div>
          </div>

          <Button onClick={handleProcess} disabled={!file || !instruction.trim() || loading}
            className="w-full bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700 shadow-lg shadow-emerald-500/20">
            {loading
              ? <><Loader2 className="w-4 h-4 animate-spin ml-2" />{step || "جارٍ المعالجة..."}</>
              : <><Wand2 className="w-4 h-4 ml-2" />معالجة بالذكاء الاصطناعي</>}
          </Button>
        </div>

        {/* Preview */}
        <div className="min-h-64">
          {result ? (
            <div className="space-y-3 h-full">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <p className="text-sm font-medium text-emerald-400">{result.summary}</p>
                </div>
                <Button size="sm" onClick={handleDownload} disabled={!result.xlsxBase64}
                  className="gap-1 bg-emerald-600 hover:bg-emerald-700 text-xs">
                  <Download className="w-3.5 h-3.5" /> تحميل Excel
                </Button>
              </div>
              <div className="overflow-auto max-h-80 border border-border rounded-xl bg-secondary/20">
                <table className="w-full text-xs">
                  <thead className="bg-secondary/80 sticky top-0">
                    <tr>
                      {result.headers.map((h, i) => (
                        <th key={i} className="px-3 py-2.5 text-right font-semibold border-b border-border text-emerald-300">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.rows.slice(0, 20).map((row, i) => {
                      const cells: any[] = Array.isArray(row)
                        ? row
                        : result.headers.map((h: string) => (row as Record<string, any>)[h]);
                      return (
                        <tr key={i} className={`border-b border-border/50 ${i % 2 === 0 ? "" : "bg-secondary/20"} hover:bg-secondary/40 transition-colors`}>
                          {cells.map((cell, j) => (
                            <td key={j} className="px-3 py-2 text-muted-foreground">{String(cell ?? "")}</td>
                          ))}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {result.rows.length > 20 && (
                  <p className="text-xs text-center text-muted-foreground/50 py-2">
                    يُعرض أول 20 صف من {result.rows.length} إجمالاً — التحميل يشمل الكل
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="h-full min-h-64 bg-secondary/20 border border-dashed border-border rounded-2xl flex items-center justify-center">
              <div className="text-center space-y-3 p-6">
                <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 flex items-center justify-center mx-auto">
                  <Table className="w-7 h-7 text-emerald-500/40" />
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">معاينة البيانات المعالجة</p>
                  <p className="text-xs text-muted-foreground/50 mt-1">ستظهر هنا بعد المعالجة</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Translation languages ─────────────────────────────────────────────────────
const TRANSLATE_LANGS = [
  { code: "العربية",    label: "🇸🇦 العربية" },
  { code: "English",    label: "🇺🇸 الإنجليزية" },
  { code: "French",     label: "🇫🇷 الفرنسية" },
  { code: "German",     label: "🇩🇪 الألمانية" },
  { code: "Spanish",    label: "🇪🇸 الإسبانية" },
  { code: "Italian",    label: "🇮🇹 الإيطالية" },
  { code: "Portuguese", label: "🇧🇷 البرتغالية" },
  { code: "Chinese",    label: "🇨🇳 الصينية" },
  { code: "Japanese",   label: "🇯🇵 اليابانية" },
  { code: "Korean",     label: "🇰🇷 الكورية" },
  { code: "Turkish",    label: "🇹🇷 التركية" },
  { code: "Russian",    label: "🇷🇺 الروسية" },
  { code: "Dutch",      label: "🇳🇱 الهولندية" },
  { code: "Persian",    label: "🇮🇷 الفارسية" },
  { code: "Hindi",      label: "🇮🇳 الهندية" },
  { code: "Urdu",       label: "🇵🇰 الأردية" },
  { code: "Indonesian", label: "🇮🇩 الإندونيسية" },
];

// ─── TAB 5: AI Office Tools ───────────────────────────────────────────────────
function AIToolsTab() {
  const [activeTool, setActiveTool] = useState("summarize");
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [loading, setLoading] = useState(false);
  const [lang, setLang] = useState("ar");
  const [targetLang, setTargetLang] = useState("English");

  const tools = [
    { id: "summarize", label: "تلخيص ذكي",    icon: FileText,      color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30" },
    { id: "translate", label: "ترجمة فورية",   icon: Languages,    color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30" },
    { id: "grammar",   label: "تدقيق لغوي",    icon: SpellCheck,   color: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/30" },
    { id: "email",     label: "كتابة إيميل",   icon: Mail,         color: "text-pink-400",   bg: "bg-pink-500/10",   border: "border-pink-500/30" },
    { id: "minutes",   label: "محضر اجتماع",   icon: ClipboardList,color: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/30" },
    { id: "letter",    label: "خطاب رسمي",     icon: FileSignature,color: "text-cyan-400",   bg: "bg-cyan-500/10",   border: "border-cyan-500/30" },
    { id: "contract",  label: "عقد قانوني",    icon: FileSignature,color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30" },
    { id: "cv",        label: "سيرة ذاتية",    icon: FileText,     color: "text-indigo-400", bg: "bg-indigo-500/10", border: "border-indigo-500/30" },
    { id: "proposal",  label: "مقترح مشروع",   icon: Briefcase,    color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
    { id: "invoice",   label: "فاتورة",        icon: ClipboardList,color: "text-teal-400",   bg: "bg-teal-500/10",   border: "border-teal-500/30" },
  ];

  const activeDef = tools.find(t => t.id === activeTool)!;

  const placeholders: Record<string, string> = {
    summarize: "الصق النص الذي تريد تلخيصه هنا — يعمل مع المقالات والتقارير والوثائق...",
    translate: "الصق النص الذي تريد ترجمته هنا...",
    grammar: "الصق النص الذي تريد تدقيقه لغوياً هنا...",
    email: "مثال: إيميل لتأكيد موعد اجتماع مع العميل أحمد...",
    minutes: "الصق ملاحظات الاجتماع هنا (النقاط الرئيسية، القرارات)...",
    letter: "مثال: خطاب توصية لموظف اسمه محمد علي...",
    contract: "مثال: عقد توظيف بين شركة XYZ والموظف أحمد، راتب 5000...",
    cv: "مثال: اسمي أحمد، خبرة 5 سنوات في التسويق الرقمي، بكالوريوس إدارة أعمال...",
    proposal: "مثال: مقترح مشروع تطبيق إدارة المخزون لشركة ABC، ميزانية 50,000...",
    invoice: "مثال: فاتورة لعميل شركة النور، 3 خدمات استشارية بقيمة 2000 لكل منها...",
  };

  const inputLabels: Record<string, string> = {
    summarize: "النص المراد تلخيصه",
    translate: "النص المراد ترجمته",
    grammar: "النص المراد تدقيقه",
    email: "نقاط ومتطلبات الإيميل",
    minutes: "ملاحظات الاجتماع",
    letter: "تفاصيل الخطاب المطلوب",
    contract: "تفاصيل العقد (الأطراف، الشروط)",
    cv: "بياناتك الشخصية والمهنية",
    proposal: "تفاصيل المقترح (المشروع، الأهداف، الميزانية)",
    invoice: "بيانات الفاتورة (العميل، الخدمات، الأسعار)",
  };

  const handleRun = async () => {
    if (!input.trim()) { toast.error("يرجى إدخال النص أولاً"); return; }
    setLoading(true);
    setOutput("");
    try {
      const res = await fetch(`${API_BASE}/api/office/run-tool`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ toolId: activeTool, text: input, language: lang, extraOption: activeTool === "translate" ? targetLang : "" }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "فشل تنفيذ الأداة");
      setOutput(data.result || "");
    } catch (err: any) {
      toast.error(err.message || "حدث خطأ");
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!output) return;
    navigator.clipboard.writeText(output);
    toast.success("تم النسخ إلى الحافظة ✓");
  };

  const handleDownloadDocx = async () => {
    if (!output) return;
    try {
      const res = await fetch(`${API_BASE}/api/office/text-to-docx`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ text: output, filename: activeDef.label }),
      });
      if (!res.ok) throw new Error("فشل إنشاء الملف");
      const blob = await res.blob();
      downloadBlob(blob, `${activeDef.label}.docx`);
      toast.success("تم تحميل ملف Word!");
    } catch (err: any) {
      toast.error(err.message || "فشل التحميل");
    }
  };

  return (
    <div className="space-y-5">
      <SectionHeader
        icon={Wand2}
        title="أدوات الذكاء الاصطناعي للكتابة المكتبية"
        desc="10 أدوات احترافية: تلخيص، ترجمة، تدقيق، إيميلات، محاضر، خطابات، عقود، سيرة ذاتية، مقترحات، وفواتير"
        gradient="from-violet-600/80 to-purple-700/80"
      />

      {/* Tool Selector */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
        {tools.map(t => (
          <button key={t.id}
            onClick={() => { if (activeTool !== t.id) { setActiveTool(t.id); setOutput(""); } }}
            className={`flex flex-col items-center gap-2 px-2 py-3.5 rounded-xl text-xs border transition-all ${
              activeTool === t.id
                ? `${t.border} ${t.bg} ${t.color} font-semibold shadow-sm`
                : "border-border text-muted-foreground hover:border-primary/40 hover:text-foreground hover:bg-secondary/50"
            }`}>
            <t.icon className={`w-5 h-5 ${activeTool === t.id ? t.color : "text-muted-foreground"}`} />
            <span className="text-center leading-tight">{t.label}</span>
          </button>
        ))}
      </div>

      <div className="grid lg:grid-cols-2 gap-5">
        {/* Input Side */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium text-muted-foreground">{inputLabels[activeTool]}</label>
            {activeTool !== "translate" && (
              <div className="flex gap-2">
                <button onClick={() => setLang("ar")} className={`px-2.5 py-1 rounded-lg text-xs border transition-all ${lang === "ar" ? "border-primary text-primary bg-primary/10" : "border-border text-muted-foreground hover:border-primary/30"}`}>🇸🇦 عربي</button>
                <button onClick={() => setLang("en")} className={`px-2.5 py-1 rounded-lg text-xs border transition-all ${lang === "en" ? "border-primary text-primary bg-primary/10" : "border-border text-muted-foreground hover:border-primary/30"}`}>🇺🇸 EN</button>
              </div>
            )}
          </div>

          {activeTool === "translate" && (
            <div className="bg-secondary/30 border border-border rounded-xl p-3 space-y-2">
              <p className="text-xs font-medium text-muted-foreground">اللغة المستهدفة:</p>
              <div className="grid grid-cols-2 gap-1.5 max-h-36 overflow-y-auto pl-1">
                {TRANSLATE_LANGS.map(l => (
                  <button key={l.code} onClick={() => setTargetLang(l.code)}
                    className={`px-2.5 py-1.5 rounded-lg text-xs border text-right transition-all ${targetLang === l.code ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400 font-medium" : "border-border/50 text-muted-foreground hover:border-primary/30 hover:text-foreground"}`}>
                    {l.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="relative">
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              rows={11}
              dir="auto"
              placeholder={placeholders[activeTool]}
              className="w-full px-4 py-3 bg-secondary/50 border border-border rounded-xl text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary/50 placeholder:text-muted-foreground/40 transition-all"
            />
            {input && (
              <p className="absolute bottom-3 left-3 text-xs text-muted-foreground/40">
                {input.length} حرف • {input.split(/\s+/).filter(Boolean).length} كلمة
              </p>
            )}
          </div>

          <Button onClick={handleRun} disabled={!input.trim() || loading}
            className="w-full bg-gradient-to-r from-violet-500 to-purple-600 hover:from-violet-600 hover:to-purple-700 shadow-lg shadow-violet-500/20">
            {loading
              ? <><Loader2 className="w-4 h-4 animate-spin ml-2" />جارٍ المعالجة...</>
              : <><activeDef.icon className="w-4 h-4 ml-2" />{activeDef.label}</>}
          </Button>
        </div>

        {/* Output Side */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium text-muted-foreground">النتيجة</label>
            {output && (
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={handleCopy} className="h-7 text-xs gap-1 hover:bg-primary/10 hover:text-primary hover:border-primary/40">
                  <Copy className="w-3 h-3" /> نسخ
                </Button>
                <Button size="sm" variant="outline" onClick={handleDownloadDocx} className="h-7 text-xs gap-1 hover:bg-blue-500/10 hover:text-blue-400 hover:border-blue-500/40">
                  <Download className="w-3 h-3" /> Word
                </Button>
              </div>
            )}
          </div>
          <div className="min-h-80 bg-secondary/30 border border-border rounded-xl p-4 text-sm overflow-auto relative">
            {loading ? (
              <div className="flex flex-col items-center justify-center h-full min-h-64 gap-3 text-muted-foreground">
                <Loader2 className="w-8 h-8 animate-spin text-primary/50" />
                <p className="text-sm">جارٍ المعالجة بالذكاء الاصطناعي...</p>
              </div>
            ) : output ? (
              <>
                <p className="text-foreground leading-relaxed whitespace-pre-wrap" dir="auto">{output}</p>
                {output && (
                  <p className="text-xs text-muted-foreground/40 mt-4 pt-3 border-t border-border/50">
                    {output.length} حرف • {output.split(/\s+/).filter(Boolean).length} كلمة
                  </p>
                )}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center h-full min-h-64 gap-3">
                <div className={`w-12 h-12 rounded-2xl ${activeDef.bg} flex items-center justify-center`}>
                  <activeDef.icon className={`w-6 h-6 ${activeDef.color}`} />
                </div>
                <p className="text-sm text-muted-foreground/60">ستظهر النتيجة هنا بعد المعالجة</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── TAB 6: OCR ───────────────────────────────────────────────────────────────
function OCRTab() {
  const [image, setImage] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  const handleImageInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 10 * 1024 * 1024) { toast.error("حجم الصورة يتجاوز 10 MB"); return; }
    setImage(f);
    setText("");
    const reader = new FileReader();
    reader.onload = ev => setPreview(ev.target?.result as string);
    reader.readAsDataURL(f);
  };

  const handleExtract = async () => {
    if (!image) return;
    setLoading(true);
    setProgress(0);
    try {
      const Tesseract = await import("tesseract.js");
      const result = await Tesseract.recognize(image, "ara+eng", {
        logger: (m: any) => {
          if (m.status === "recognizing text") setProgress(Math.round(m.progress * 100));
        },
      });
      setText(result.data.text);
      toast.success("تم استخراج النص بنجاح! ✓");
    } catch {
      toast.error("فشل استخراج النص. تأكد من وضوح الصورة وجودتها.");
    } finally {
      setLoading(false);
      setProgress(0);
    }
  };

  const handleCopy = () => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    toast.success("تم النسخ إلى الحافظة ✓");
  };

  const handleDownload = async () => {
    if (!text) return;
    try {
      const res = await fetch(`${API_BASE}/api/office/text-to-docx`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ text, filename: "النص المستخرج" }),
      });
      if (!res.ok) throw new Error("فشل إنشاء الملف");
      const blob = await res.blob();
      downloadBlob(blob, "النص المستخرج.docx");
      toast.success("تم تحميل ملف Word!");
    } catch (err: any) {
      toast.error(err.message || "فشل التحميل");
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        icon={ScanText}
        title="استخراج النصوص من الصور (OCR)"
        desc="ارفع صورة تحتوي على نص مكتوب وسيتم استخراجه تلقائياً — يدعم العربية والإنجليزية وأكثر من 20 لغة"
        gradient="from-amber-600/80 to-orange-700/80"
      />

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Image Upload */}
        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">رفع صورة تحتوي على نص</label>
            <label className="block border-2 border-dashed border-border rounded-2xl overflow-hidden cursor-pointer hover:border-amber-500/50 transition-all group">
              {preview ? (
                <div className="relative">
                  <img src={preview} alt="معاينة" className="w-full h-56 object-contain bg-black/30" />
                  <div className="absolute inset-0 bg-black/0 group-hover:bg-black/20 transition-colors flex items-center justify-center">
                    <p className="text-white text-sm font-medium opacity-0 group-hover:opacity-100 transition-opacity">انقر لتغيير الصورة</p>
                  </div>
                </div>
              ) : (
                <div className="h-56 flex flex-col items-center justify-center gap-4">
                  <div className="w-16 h-16 rounded-2xl bg-amber-500/10 flex items-center justify-center group-hover:bg-amber-500/20 group-hover:scale-110 transition-all duration-300">
                    <ScanText className="w-8 h-8 text-amber-400/60" />
                  </div>
                  <div className="text-center">
                    <p className="text-sm font-medium text-muted-foreground">اضغط لاختيار صورة</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">PNG · JPG · JPEG — حتى 10 MB</p>
                  </div>
                </div>
              )}
              <input type="file" accept="image/png,image/jpg,image/jpeg" className="hidden" onChange={handleImageInput} />
            </label>
          </div>

          {loading && (
            <div className="space-y-2 bg-amber-950/20 border border-amber-500/20 rounded-xl p-4">
              <div className="flex items-center justify-between text-sm">
                <span className="text-amber-300 flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  جارٍ تحليل الصورة واستخراج النص...
                </span>
                <span className="font-mono text-amber-400 font-bold">{progress}%</span>
              </div>
              <div className="w-full bg-secondary rounded-full h-2.5 overflow-hidden">
                <div className="bg-gradient-to-r from-amber-500 to-orange-500 h-2.5 rounded-full transition-all" style={{ width: `${progress}%` }} />
              </div>
            </div>
          )}

          <Button onClick={handleExtract} disabled={!image || loading}
            className="w-full bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-600 hover:to-orange-700 shadow-lg shadow-amber-500/20">
            {loading
              ? <><Loader2 className="w-4 h-4 animate-spin ml-2" />جارٍ الاستخراج... {progress}%</>
              : <><ScanText className="w-4 h-4 ml-2" />استخراج النص من الصورة</>}
          </Button>

          <div className="bg-secondary/20 rounded-xl border border-border p-4 space-y-2">
            <p className="text-xs font-semibold text-muted-foreground">اللغات المدعومة:</p>
            <div className="flex flex-wrap gap-2">
              {["🇸🇦 العربية", "🇺🇸 الإنجليزية", "🇫🇷 الفرنسية", "🇩🇪 الألمانية", "🇪🇸 الإسبانية", "والمزيد"].map(l => (
                <span key={l} className="px-2.5 py-1 bg-amber-500/10 text-amber-300 rounded-full text-xs border border-amber-500/20">{l}</span>
              ))}
            </div>
            <p className="text-xs text-muted-foreground/50 pt-1">
              نصيحة: الصور بدقة عالية ونص واضح تعطي نتائج أدق
            </p>
          </div>
        </div>

        {/* OCR Result */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium text-muted-foreground">النص المستخرج</label>
            {text && (
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={handleCopy} className="h-7 text-xs gap-1 hover:bg-primary/10 hover:text-primary hover:border-primary/40">
                  <Copy className="w-3 h-3" /> نسخ
                </Button>
                <Button size="sm" variant="outline" onClick={handleDownload} className="h-7 text-xs gap-1 hover:bg-blue-500/10 hover:text-blue-400 hover:border-blue-500/40">
                  <Download className="w-3 h-3" /> Word
                </Button>
              </div>
            )}
          </div>
          <textarea
            value={text}
            onChange={e => setText(e.target.value)}
            rows={18}
            dir="auto"
            placeholder="سيظهر النص المستخرج من الصورة هنا — يمكنك تعديله بعد الاستخراج..."
            className="w-full px-4 py-3 bg-secondary/30 border border-border rounded-xl text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary/50 placeholder:text-muted-foreground/40 transition-all"
          />
          {text && (
            <p className="text-xs text-muted-foreground/50 flex items-center gap-3">
              <span>{text.length} حرف</span>
              <span>•</span>
              <span>{text.split(/\s+/).filter(Boolean).length} كلمة</span>
              <span>•</span>
              <span>{text.split("\n").filter(Boolean).length} سطر</span>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
const TABS = [
  { id: "convert", label: "محوّل الملفات",       icon: RefreshCw,    component: FileConverterTab, color: "text-violet-400" },
  { id: "pptx",    label: "عروض PowerPoint",      icon: Presentation, component: PowerPointTab,    color: "text-indigo-400" },
  { id: "word",    label: "تقارير Word",           icon: FileText,     component: WordReportTab,    color: "text-blue-400" },
  { id: "excel",   label: "معالج Excel",           icon: Table,        component: ExcelTab,         color: "text-emerald-400" },
  { id: "tools",   label: "أدوات الكتابة الذكية", icon: Wand2,        component: AIToolsTab,       color: "text-violet-400" },
  { id: "ocr",     label: "استخراج النصوص",       icon: ScanText,     component: OCRTab,           color: "text-amber-400" },
];

export default function OfficeSuite() {
  const [activeTab, setActiveTab] = useState("convert");
  const ActiveComponent = TABS.find(t => t.id === activeTab)?.component || FileConverterTab;

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="border-b border-border bg-card/60 backdrop-blur-xl sticky top-0 z-40">
        <div className="container flex items-center justify-between h-14">
          <div className="flex items-center gap-3">
            <Link href="/" className="text-muted-foreground hover:text-primary transition-colors p-1">
              <Home className="w-4 h-4" />
            </Link>
            <span className="text-border">/</span>
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-primary/10 flex items-center justify-center">
                <Briefcase className="w-3.5 h-3.5 text-primary" />
              </div>
              <div>
                <h1 className="font-heading font-bold text-sm text-foreground">الأعمال المكتبية</h1>
                <p className="text-[10px] text-muted-foreground leading-none">مدعومة بالذكاء الاصطناعي</p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-full text-xs text-emerald-400">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              AI متصل
            </div>
            <Link href="/chat">
              <Button variant="outline" size="sm" className="text-xs gap-1.5 h-8">
                <Sparkles className="w-3.5 h-3.5" /> مساعد AI
              </Button>
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Banner */}
      <div className="border-b border-border bg-gradient-to-r from-primary/5 via-background to-primary/5">
        <div className="container py-5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-bold font-heading flex items-center gap-2">
                <Briefcase className="w-5 h-5 text-primary" />
                مجموعة الأدوات المكتبية الاحترافية
              </h2>
              <p className="text-sm text-muted-foreground mt-1">
                كل ما تحتاجه للعمل المكتبي الاحترافي — مدعوم بأقوى نماذج الذكاء الاصطناعي
              </p>
            </div>
            <div className="hidden lg:flex items-center gap-6 text-center">
              {[
                { n: "30+",  l: "صيغة ملف" },
                { n: "6",    l: "أدوات AI" },
                { n: "17",   l: "لغة ترجمة" },
              ].map(s => (
                <div key={s.l}>
                  <p className="text-2xl font-bold text-primary">{s.n}</p>
                  <p className="text-xs text-muted-foreground">{s.l}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="container py-6 space-y-4">
        {/* Tab Bar */}
        <div className="flex gap-1 overflow-x-auto pb-1 scrollbar-hide">
          {TABS.map((tab, idx) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium whitespace-nowrap transition-all shrink-0 ${
                activeTab === tab.id
                  ? "bg-primary/10 text-primary border border-primary/30 shadow-sm"
                  : "text-muted-foreground hover:text-foreground hover:bg-secondary/60 border border-transparent"
              }`}
            >
              <tab.icon className={`w-4 h-4 ${activeTab === tab.id ? "text-primary" : tab.color}`} />
              {tab.label}
              <span className={`text-xs px-1.5 py-0.5 rounded-md font-mono ${activeTab === tab.id ? "bg-primary/20 text-primary" : "bg-secondary text-muted-foreground/60"}`}>
                {idx + 1}
              </span>
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="bg-card/50 border border-border rounded-2xl p-6 shadow-sm">
          <ActiveComponent />
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-muted-foreground/40 py-2">
          HAYO AI Office Suite • جميع الملفات تُعالَج بشكل آمن ولا تُحفظ على خوادمنا
        </p>
      </div>
    </div>
  );
}
