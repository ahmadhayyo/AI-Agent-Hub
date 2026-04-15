import type React from "react";
import Editor from "@monaco-editor/react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  Activity,
  Archive,
  BarChart3,
  Binary,
  BookOpen,
  Bot,
  CheckCircle2,
  Copy,
  Database,
  Download,
  Eye,
  FileCode2,
  FileJson,
  Fingerprint,
  FolderOpen,
  Info,
  Loader2,
  Lock,
  Microscope,
  Search,
  Shield,
  Wrench,
  Sparkles,
  TrendingUp,
  Unlock,
  Upload,
  X,
  Zap,
  ChevronDown,
} from "lucide-react";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import type { DecompileResult, DecompiledFile, FileTreeNode, VulnerabilityFinding } from "./types";

interface AnalysisTabProps {
  fRef: React.RefObject<HTMLInputElement | null>;
  acceptStr: string;
  allFormats: readonly string[];
  aFile: File | null;
  drag: boolean;
  decomp: boolean;
  res: DecompileResult | null;
  selNode: FileTreeNode | null;
  selContent: string;
  selBinary: DecompiledFile | null;
  analyzing: boolean;
  aiText: string;
  showAi: boolean;
  dlId: string;
  aSessId: string;
  eSessId?: string;
  treeFilter: string;
  decompStep: number;
  statsAnim: boolean;
  liveStream: { sseUrl: string } | null;
  dangerPerms: Set<string>;
  formatIconMap: Record<string, string>;
  valid: (file: File) => boolean;
  fmtB: (bytes: number) => string;
  lang: (ext: string) => string;
  registerSmaliLanguage: (monaco: unknown) => void;
  TNode: React.ComponentType<{
    node: FileTreeNode;
    onSelect: (node: FileTreeNode) => void;
    sel: string;
    filter?: string;
    mods?: Set<string>;
  }>;
  LiveTerminal: React.ComponentType<{
    sseUrl: string;
    onComplete?: () => void;
    onResult?: (data: unknown) => void;
  }>;
  ProgressSteps: React.ComponentType<{ step: number }>;
  VPanel: React.ComponentType<{ findings: VulnerabilityFinding[] }>;
  BinaryHexViewer: React.ComponentType<{ file: { name: string; size: number; extension: string; path?: string }; sessionId?: string }>;
  doDecompile: () => void;
  doSelNode: (node: FileTreeNode) => void;
  doAiAnalysis: (type: string) => void;
  doIntel: () => Promise<void> | void;
  doDecodeStrings: () => Promise<void> | void;
  handleDecompResult: (data: unknown) => void;
  handleDecompComplete: () => void;
  setDrag: React.Dispatch<React.SetStateAction<boolean>>;
  setAFile: React.Dispatch<React.SetStateAction<File | null>>;
  setRes: React.Dispatch<React.SetStateAction<DecompileResult | null>>;
  setTreeFilter: React.Dispatch<React.SetStateAction<string>>;
  setTab: React.Dispatch<React.SetStateAction<"analyze" | "clone" | "edit" | "intel" | "forensics" | "cloudpen">>;
  setShowAi: React.Dispatch<React.SetStateAction<boolean>>;
}

export function AnalysisTab(props: AnalysisTabProps) {
  const {
    fRef,
    acceptStr,
    allFormats,
    aFile,
    drag,
    decomp,
    res,
    selNode,
    selContent,
    selBinary,
    analyzing,
    aiText,
    showAi,
    dlId,
    aSessId,
    eSessId,
    treeFilter,
    decompStep,
    statsAnim,
    liveStream,
    dangerPerms,
    formatIconMap,
    valid,
    fmtB,
    lang,
    registerSmaliLanguage,
    TNode,
    LiveTerminal,
    ProgressSteps,
    VPanel,
    BinaryHexViewer,
    doDecompile,
    doSelNode,
    doAiAnalysis,
    doIntel,
    doDecodeStrings,
    handleDecompResult,
    handleDecompComplete,
    setDrag,
    setAFile,
    setRes,
    setTreeFilter,
    setTab,
    setShowAi,
  } = props;

  return (
    <div className="flex-1 grid grid-cols-1 lg:grid-cols-[280px_240px_1fr] gap-4 min-h-0">
      <div className="flex flex-col gap-3">
        <div className="flex items-center gap-2 text-xs text-muted-foreground bg-emerald-500/5 border border-emerald-500/20 rounded-lg px-3 py-2"><Info className="w-3.5 h-3.5 text-emerald-400 shrink-0"/><span>تفكيك <b className="text-emerald-300">5</b> · تحليل <b className="text-emerald-300">3</b> نقاط</span></div>
        <div className={`border-2 border-dashed rounded-2xl p-5 text-center cursor-pointer transition-all ${drag ? "border-emerald-400 bg-emerald-500/10" : "border-border hover:border-emerald-400/50"}`} onDragOver={e => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={e => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f && valid(f)) { setAFile(f); setRes(null); } }} onClick={() => fRef.current?.click()}>
          <input ref={fRef} type="file" accept={acceptStr} className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f && valid(f)) { setAFile(f); setRes(null); } }}/>
          {aFile ? <div className="space-y-2"><div className="text-3xl">{formatIconMap[aFile.name.split(".").pop()?.toLowerCase() || ""] || "📦"}</div><p className="font-medium text-sm truncate">{aFile.name}</p><p className="text-xs text-muted-foreground">{fmtB(aFile.size)}</p><button onClick={e => { e.stopPropagation(); setAFile(null); setRes(null); }} className="text-xs text-red-400"><X className="w-3 h-3 inline"/>تغيير</button></div>
          : <div className="space-y-2"><Upload className="w-8 h-8 mx-auto text-muted-foreground"/><p className="text-sm font-medium">اسحب أو انقر</p><p className="text-[10px] text-muted-foreground">{allFormats.map(f => f.toUpperCase()).join(" · ")}</p></div>}
        </div>
        {aFile && !res && !decomp && <Button onClick={doDecompile} className="w-full gap-2 bg-emerald-600 hover:bg-emerald-700 py-5"><Binary className="w-4 h-4"/>تفكيك</Button>}
        {decomp && <><ProgressSteps step={decompStep}/>{liveStream && <LiveTerminal sseUrl={liveStream.sseUrl} onResult={handleDecompResult} onComplete={handleDecompComplete}/>}</>}
        {res && <div className="space-y-2">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0"/>
            <span className="text-sm font-bold text-emerald-300">اكتمل التفكيك</span>
            {dlId && <Button size="sm" variant="outline" onClick={() => window.open(`/api/reverse/download/${dlId}`, "_blank")} className="mr-auto h-7 text-[10px] gap-1 border-emerald-500/30"><Archive className="w-3 h-3"/>ZIP</Button>}
          </div>
          <div className="grid grid-cols-2 gap-1.5">
            {([
              { icon: Database, label: "الملفات", value: String(res.totalFiles), color: "text-emerald-300", bg: "from-emerald-500/10 to-emerald-500/5", border: "border-emerald-500/25", delay: 0 },
              { icon: BarChart3, label: "الحجم", value: fmtB(res.totalSize), color: "text-cyan-300", bg: "from-cyan-500/10 to-cyan-500/5", border: "border-cyan-500/25", delay: 80 },
              { icon: FileCode2, label: "الصيغة", value: (res.formatLabel || res.fileType || "—").toUpperCase(), color: "text-blue-300", bg: "from-blue-500/10 to-blue-500/5", border: "border-blue-500/25", delay: 160 },
              { icon: Sparkles, label: "نموذج AI", value: res.metadata?.aiModelUsed ? res.metadata.aiModelUsed.replace("claude-", "").replace("gpt-", "GPT-").slice(0, 10) : "—", color: "text-violet-300", bg: "from-violet-500/10 to-violet-500/5", border: "border-violet-500/25", delay: 240 },
            ]).map(({ icon: Icon, label, value, color, bg, border, delay }) => (
              <div key={label} className={`bg-gradient-to-br ${bg} border ${border} rounded-xl p-2.5 text-center transition-all duration-500`} style={{ opacity: statsAnim ? 1 : 0, transform: statsAnim ? "translateY(0)" : "translateY(8px)", transitionDelay: `${delay}ms` }}>
                <Icon className={`w-3.5 h-3.5 mx-auto mb-1 ${color} opacity-70`}/>
                <div className={`text-base font-black ${color} leading-tight truncate`}>{value}</div>
                <div className="text-[9px] text-muted-foreground mt-0.5">{label}</div>
              </div>
            ))}
          </div>
        </div>}
        {res && aSessId && <div className="bg-gradient-to-br from-cyan-500/10 to-violet-500/10 border border-cyan-500/30 rounded-xl p-3 space-y-2 animate-in fade-in slide-in-from-top-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-cyan-300"><Zap className="w-4 h-4"/>الملف جاهز للتحليل المتقدم</div>
          <div className="grid grid-cols-2 gap-2">
            <button onClick={() => { setTab("intel"); setTimeout(() => { void doIntel(); }, 300); }} className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 transition-all text-xs font-medium"><Fingerprint className="w-4 h-4"/>استخبارات تلقائية</button>
            <button onClick={() => { setTab("forensics"); setTimeout(() => { void doDecodeStrings(); }, 300); }} className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-violet-500/10 border border-violet-500/30 text-violet-300 hover:bg-violet-500/20 transition-all text-xs font-medium"><Microscope className="w-4 h-4"/>طب شرعي تلقائي</button>
          </div>
          <button onClick={async () => { toast.info("جاري التحليل الشامل..."); setTab("intel"); setTimeout(async () => { await doIntel(); setTab("forensics"); setTimeout(() => { void doDecodeStrings(); }, 300); }, 300); }} className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-gradient-to-r from-cyan-600/80 to-violet-600/80 text-white hover:from-cyan-500 hover:to-violet-500 transition-all text-xs font-bold"><Sparkles className="w-4 h-4"/>تحليل تلقائي شامل (استخبارات + طب شرعي)</button>
        </div>}
        {res?.manifest?.permissions?.length > 0 && <div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-3 space-y-2"><div className="flex items-center gap-2 text-sm font-semibold"><FileJson className="w-4 h-4 text-blue-400"/>صلاحيات</div><div className="max-h-32 overflow-y-auto space-y-0.5">{((res?.manifest as { permissions?: string[] } | undefined)?.permissions ?? []).map((p: string) => <div key={p} className="flex items-center gap-1.5 text-xs">{dangerPerms.has(p) ? <Unlock className="w-3 h-3 text-red-400"/> : <Lock className="w-3 h-3 text-muted-foreground"/>}<span className={dangerPerms.has(p) ? "text-red-300" : "text-muted-foreground"}>{p}</span></div>)}</div></div>}
        {res?.vulnerabilities && res.vulnerabilities.length > 0 && <VPanel findings={res.vulnerabilities}/>}
      </div>

      <div className="bg-card/70 backdrop-blur-sm border border-border rounded-2xl overflow-hidden flex flex-col">
        <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border bg-muted/20"><FolderOpen className="w-4 h-4 text-amber-400"/><span className="text-sm font-medium">الملفات</span>{res && <span className="mr-auto text-xs text-muted-foreground">{res.totalFiles}</span>}</div>
        {res && <div className="px-2 pt-2 pb-1 border-b border-border/50"><div className="flex items-center gap-1.5 bg-muted/30 border border-border rounded-lg px-2 py-1"><Search className="w-3 h-3 text-muted-foreground shrink-0"/><input value={treeFilter} onChange={e => setTreeFilter(e.target.value)} placeholder="بحث في الملفات..." className="flex-1 bg-transparent text-xs outline-none text-right placeholder:text-muted-foreground/50 min-w-0"/>{treeFilter && <button onClick={() => setTreeFilter("")} className="shrink-0"><X className="w-3 h-3 text-muted-foreground hover:text-foreground"/></button>}</div></div>}
        <div className="flex-1 overflow-y-auto p-1">{!res ? <div className="flex flex-col items-center justify-center h-full py-12 text-muted-foreground text-sm"><FolderOpen className="w-10 h-10 mb-2 opacity-20"/><p>ارفع ملفاً</p></div> : res.structure.map((n, i) => <TNode key={i} node={n} onSelect={doSelNode} sel={selNode?.path || ""} filter={treeFilter}/>)}</div>
      </div>

      <div className="flex flex-col gap-3 min-h-0">
        <div className="bg-card/70 backdrop-blur-sm border border-border rounded-2xl overflow-hidden flex flex-col" style={{ minHeight: "300px", flex: 1 }}>
          <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-muted/20 shrink-0">
            <FileCode2 className="w-4 h-4 text-primary"/><span className="text-sm font-medium truncate flex-1">{selNode?.name || "اختر ملفاً"}</span>
            {selContent && !selContent.startsWith("[") && <div className="flex items-center gap-1">
              <DropdownMenu><DropdownMenuTrigger asChild><Button size="sm" variant="outline" disabled={analyzing} className="gap-1.5 h-7 px-2 text-xs border-primary/30"><Bot className="w-3.5 h-3.5 text-primary"/>AI<ChevronDown className="w-3 h-3"/></Button></DropdownMenuTrigger><DropdownMenuContent align="start" className="w-40 z-50"><DropdownMenuItem onClick={() => doAiAnalysis("explain")} className="gap-2 text-xs cursor-pointer"><BookOpen className="w-3 h-3"/>شرح</DropdownMenuItem><DropdownMenuItem onClick={() => doAiAnalysis("security")} className="gap-2 text-xs cursor-pointer"><Shield className="w-3 h-3 text-red-400"/>أمني</DropdownMenuItem><DropdownMenuItem onClick={() => doAiAnalysis("logic")} className="gap-2 text-xs cursor-pointer"><Wrench className="w-3 h-3 text-blue-400"/>منطق</DropdownMenuItem><DropdownMenuItem onClick={() => doAiAnalysis("full")} className="gap-2 text-xs cursor-pointer"><Bot className="w-3 h-3 text-primary"/>شامل</DropdownMenuItem></DropdownMenuContent></DropdownMenu>
              <Button size="sm" variant="ghost" onClick={() => { void navigator.clipboard.writeText(selContent); toast.success("نسخ"); }} className="h-7 w-7 p-0"><Copy className="w-3.5 h-3.5"/></Button>
              <Button size="sm" variant="ghost" onClick={() => { const b = new Blob([selContent], { type: "text/plain" }); const u = URL.createObjectURL(b); const a = document.createElement("a"); a.href = u; a.download = selNode?.name || "file"; a.click(); }} className="h-7 w-7 p-0"><Download className="w-3.5 h-3.5"/></Button>
            </div>}
          </div>
          <div className="flex-1 min-h-0">{selBinary
            ? <BinaryHexViewer file={selBinary} sessionId={aSessId || eSessId}/>
            : selContent
            ? <Editor height="100%" language={lang(selNode?.name?.includes(".") ? "." + selNode.name.split(".").pop()! : "")} value={selContent} theme={selNode?.name?.endsWith(".smali") ? "smali-dark" : "vs-dark"} beforeMount={registerSmaliLanguage} options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12, wordWrap: "on", scrollBeyondLastLine: false, renderLineHighlight: "none", lineNumbers: "on", folding: true, automaticLayout: true }}/>
            : <div className="flex flex-col items-center justify-center h-full p-6 gap-4 text-center">
                <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 border border-emerald-500/30 flex items-center justify-center"><FileCode2 className="w-7 h-7 text-emerald-400 opacity-60"/></div>
                <div><p className="text-sm font-semibold text-muted-foreground">اختر ملفاً من الشجرة</p><p className="text-[11px] text-muted-foreground/50 mt-1">لعرض الكود مع تلوين صياغي كامل</p></div>
                <div className="w-full max-w-[220px] space-y-1.5">
                  {([
                    [Database, "قراءة البنية الداخلية", "text-emerald-400"],
                    [Activity, "تحليل السلوك والأذونات", "text-blue-400"],
                    [TrendingUp, "كشف الثغرات الأمنية", "text-orange-400"],
                  ] as const).map(([Icon, label, cls]) => (
                    <div key={label} className="flex items-center gap-2 bg-muted/20 rounded-lg px-3 py-2 border border-border/50">
                      <Icon className={`w-3.5 h-3.5 shrink-0 ${cls}`}/>
                      <span className="text-[11px] text-muted-foreground">{label}</span>
                    </div>
                  ))}
                </div>
              </div>}</div>
        </div>
        {showAi && <div className="bg-card/70 backdrop-blur-sm border border-primary/30 rounded-2xl overflow-hidden flex flex-col" style={{ maxHeight: "380px" }}><div className="flex items-center gap-2 px-3 py-2.5 border-b border-border bg-primary/5 shrink-0"><Bot className="w-4 h-4 text-primary"/><span className="text-sm font-medium">AI</span><Button size="sm" variant="ghost" onClick={() => setShowAi(false)} className="mr-auto h-6 w-6 p-0"><X className="w-3 h-3"/></Button></div><div className="flex-1 overflow-y-auto p-4 text-sm leading-relaxed">{analyzing ? <div className="flex items-center gap-3 justify-center py-12 text-muted-foreground"><Loader2 className="w-5 h-5 animate-spin text-primary"/>يحلل...</div> : <div className="whitespace-pre-wrap">{aiText}</div>}</div></div>}
      </div>
    </div>
  );
}
