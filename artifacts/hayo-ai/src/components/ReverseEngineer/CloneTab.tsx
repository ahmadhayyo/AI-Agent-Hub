import {
  Upload,
  X,
  ToggleLeft,
  ToggleRight,
  Loader2,
  Rocket,
  AlertTriangle,
  CheckCircle2,
  Download,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import type { CloneOptions, CloneResult, LiveStreamState } from "./types";

interface CloneTabProps {
  cFile: File | null;
  cloning: boolean;
  cloneLive: LiveStreamState | null;
  cOpts: CloneOptions;
  cResult: CloneResult | null;
  cfRef: React.RefObject<HTMLInputElement | null>;
  acceptStr: string;
  allFormats: readonly string[];
  formatIconMap: Record<string, string>;
  fmtB: (bytes: number) => string;
  valid: (file: File) => boolean;
  setCFile: React.Dispatch<React.SetStateAction<File | null>>;
  setCResult: React.Dispatch<React.SetStateAction<CloneResult | null>>;
  setCOpts: React.Dispatch<React.SetStateAction<CloneOptions>>;
  doClone: () => void;
  LiveTerminal: React.ComponentType<{
    sseUrl: string;
    onComplete?: () => void;
    onResult?: (data: unknown) => void;
  }>;
  handleCloneResult: (data: unknown) => void;
  handleCloneComplete: () => void;
}

export default function CloneTab({
  cFile,
  cloning,
  cloneLive,
  cOpts,
  cResult,
  cfRef,
  acceptStr,
  allFormats,
  formatIconMap,
  fmtB,
  valid,
  setCFile,
  setCResult,
  setCOpts,
  doClone,
  LiveTerminal,
  handleCloneResult,
  handleCloneComplete,
}: CloneTabProps) {
  return (
    <div className="flex-1 flex flex-col gap-4 max-w-3xl mx-auto w-full">
      <div className="text-center space-y-2"><div className="w-14 h-14 mx-auto rounded-2xl bg-gradient-to-br from-violet-500/30 to-pink-500/30 flex items-center justify-center border border-violet-500/30"><GitBranchIcon className="w-7 h-7 text-violet-400"/></div><h2 className="text-xl font-bold">App Cloner</h2><p className="text-sm text-muted-foreground">تفكيك → تعديل → توقيع → بناء تلقائي</p></div>
      <div className="border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer hover:border-violet-400/50 transition-all" onClick={() => cfRef.current?.click()}>
        <input ref={cfRef} type="file" accept={acceptStr} className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f && valid(f)) setCFile(f); }} />
        {cFile ? <div className="space-y-2"><span className="text-3xl">{formatIconMap[cFile.name.split(".").pop()?.toLowerCase() || ""] || "📦"}</span><p className="font-medium">{cFile.name}</p><p className="text-sm text-muted-foreground">{fmtB(cFile.size)}</p><button onClick={e => { e.stopPropagation(); setCFile(null); setCResult(null); }} className="text-xs text-red-400"><X className="w-3 h-3 inline"/>تغيير</button></div>
        : <div className="space-y-2"><Upload className="w-8 h-8 mx-auto text-muted-foreground"/><p className="text-sm">اسحب أو انقر</p><p className="text-xs text-muted-foreground">{allFormats.map(f => f.toUpperCase()).join(" · ")}</p></div>}
      </div>
      <div className="grid grid-cols-2 gap-3">
        {([["removeAds", "إزالة الإعلانات", "🚫", "AdMob, Facebook, Unity"], ["unlockPremium", "فتح المدفوع", "🔓", "isPremium, isSubscribed"], ["removeTracking", "إزالة التتبع", "📡", "Firebase, Analytics"], ["removeLicenseCheck", "تجاوز الرخصة", "🔑", "checkLicense, verifySignature"]] as const).map(([k, l, ic, d]) => <button key={k} onClick={() => setCOpts(p => ({ ...p, [k]: !p[k as keyof typeof p] }))} className={`p-3 rounded-xl border text-right transition-all ${cOpts[k as keyof typeof cOpts] ? "bg-violet-500/10 border-violet-500/40 text-violet-300" : "bg-card/70 backdrop-blur-sm border-border text-muted-foreground hover:border-violet-500/30"}`}><div className="flex items-center gap-2"><span className="text-lg">{ic}</span><span className="font-medium text-sm">{l}</span><span className="mr-auto">{cOpts[k as keyof typeof cOpts] ? <ToggleRight className="w-5 h-5 text-violet-400"/> : <ToggleLeft className="w-5 h-5"/>}</span></div><p className="text-[10px] mt-1 opacity-60">{d}</p></button>)}
      </div>
      <div className="grid grid-cols-2 gap-3">
        <input value={cOpts.changeAppName} onChange={e => setCOpts(p => ({ ...p, changeAppName: e.target.value }))} placeholder="اسم جديد (اختياري)" className="bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm text-right placeholder:text-muted-foreground/50 focus:outline-none focus:border-violet-500/50"/>
        <input value={cOpts.changePackageName} onChange={e => setCOpts(p => ({ ...p, changePackageName: e.target.value }))} placeholder="حزمة جديدة (اختياري)" className="bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm text-right placeholder:text-muted-foreground/50 focus:outline-none focus:border-violet-500/50 font-mono"/>
      </div>
      <textarea value={cOpts.customInstructions} onChange={e => setCOpts(p => ({ ...p, customInstructions: e.target.value }))} placeholder="تعليمات إضافية للذكاء الاصطناعي..." rows={2} className="bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm text-right placeholder:text-muted-foreground/50 resize-none"/>
      <Button onClick={doClone} disabled={!cFile || cloning} className="w-full gap-2 py-6 text-base bg-gradient-to-r from-violet-600 to-pink-600 hover:from-violet-500 hover:to-pink-500">{cloning ? <><Loader2 className="w-5 h-5 animate-spin"/>جاري الاستنساخ...</> : <><Rocket className="w-5 h-5"/>استنساخ الآن</>}</Button>
      {cloning && cloneLive && <LiveTerminal sseUrl={cloneLive.sseUrl} onResult={handleCloneResult} onComplete={handleCloneComplete}/>}
      {cResult && !cResult.success && <div className="bg-card/70 backdrop-blur-sm border border-red-500/20 rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-red-400"/><span className="text-sm font-bold text-red-300">فشل الاستنساخ</span></div>
        {cResult.modifications.length > 0 && <div className="max-h-40 overflow-y-auto space-y-1">{cResult.modifications.map((m: string, i: number) => <div key={i} className="text-xs bg-muted/20 rounded px-2 py-1 text-muted-foreground">{m}</div>)}</div>}
      </div>}
      {cResult && cResult.success && <div className="bg-card/70 backdrop-blur-sm border border-emerald-500/20 rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2"><CheckCircle2 className="w-5 h-5 text-emerald-400"/><span className="text-sm font-bold text-emerald-300">استنساخ ناجح</span></div>
        <div className="grid grid-cols-3 gap-2">
          <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-2 text-center"><div className="text-lg font-bold text-emerald-300">{cResult.modifications.length}</div><div className="text-[10px] text-muted-foreground">تعديل</div></div>
          <div className="bg-violet-500/10 border border-violet-500/30 rounded-lg p-2 text-center"><div className="text-lg font-bold text-violet-300">{cResult.patchedFiles || 0}</div><div className="text-[10px] text-muted-foreground">ملف معدّل</div></div>
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-2 text-center"><div className="text-lg font-bold text-blue-300">{cResult.signed ? "موقّع" : "غير موقّع"}</div><div className="text-[10px] text-muted-foreground">التوقيع</div></div>
        </div>
        <div className="text-xs font-semibold text-muted-foreground">سجل التعديلات:</div>
        <div className="max-h-56 overflow-y-auto space-y-1.5">{cResult.modifications.map((m: string, i: number) => <div key={i} className="text-xs bg-muted/20 rounded-lg px-3 py-2 flex items-start gap-2 border border-border/50"><span className="text-emerald-400 shrink-0 mt-0.5">{m.includes("إزالة") ? "🗑️" : m.includes("تغيير") ? "✏️" : m.includes("تعطيل") ? "⛔" : m.includes("توقيع") ? "🔏" : "✅"}</span><span className="text-muted-foreground">{m}</span></div>)}</div>
        {cResult.downloadUrl && <a href={cResult.downloadUrl} download className="flex items-center justify-center gap-2 w-full py-3 rounded-xl bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-semibold text-sm transition-all"><Download className="w-4 h-4"/>تحميل الملف المعدّل</a>}
        {cResult.installCommand && <div className="bg-muted/30 border border-border rounded-lg p-2 font-mono text-xs text-muted-foreground"><span className="text-emerald-400">$</span> {cResult.installCommand}</div>}
      </div>}
    </div>
  );
}

function GitBranchIcon(props: { className?: string }) {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={props.className}><path d="M6 3v12"/><path d="M18 9a3 3 0 1 0-3-3"/><path d="M6 15a3 3 0 1 0 3 3"/><path d="M18 6v6a9 9 0 0 1-9 9"/></svg>;
}
