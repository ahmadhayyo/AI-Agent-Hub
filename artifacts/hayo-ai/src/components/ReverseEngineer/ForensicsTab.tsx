import type React from "react";
import Editor from "@monaco-editor/react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  AlertTriangle,
  Braces,
  CheckCircle2,
  Diff,
  FileCode2,
  FileOutput,
  FolderOpen,
  Hash,
  Layers,
  Link2,
  Loader2,
  Microscope,
  Network,
  Search,
  Upload,
  X,
  Zap,
} from "lucide-react";
import type { FileTreeNode } from "./types";

type ForensicsPanel = "decode" | "xref" | "hierarchy" | "dataflow" | "methods" | "diff" | "report";

interface ForensicsTabProps {
  sharedTree: FileTreeNode[];
  forensicsTreeFilter: string;
  forensicsSelNode: FileTreeNode | null;
  forensicsSelContent: string;
  iSess: string;
  aFile: File | null;
  eFile: File | null;
  fPanel: ForensicsPanel;
  fDecoded: Array<{ encoding: string; file: string; line: number; confidence: number; original: string; decoded: string }>;
  fDecodedLoading: boolean;
  fXref: { totalCount: number; target: string; references: Array<{ type: string; file: string; line: number; context: string }> } | null;
  fXrefLoading: boolean;
  fXrefQuery: string;
  fHierarchy: {
    stats: { totalClasses: number; interfaces: number; abstractClasses: number; maxDepth: number };
    classes: Array<{ name: string; children: string[]; methods: number; fields: number; superClass: string; isInterface: boolean; isAbstract: boolean }>;
  } | null;
  fHierarchyLoading: boolean;
  fDataFlow: {
    sensitiveApis: Array<{ category: string; api: string; file: string; line: number; context: string; dataFlow?: string[] }>;
    sinks: unknown[];
    sources: unknown[];
  } | null;
  fDataFlowLoading: boolean;
  fMethodSearch: {
    totalFound: number;
    methods: Array<{ methodName: string; signature: string; file: string; line: number; linesOfCode: number; registers: number; modifiers: string }>;
  } | null;
  fMethodLoading: boolean;
  fMethodQuery: string;
  fDiff: {
    summary?: {
      totalAdded?: number;
      totalRemoved?: number;
      totalModified?: number;
      totalUnchanged?: number;
      versionChange?: { old: string; new: string };
      permissionChanges?: { added?: string[]; removed?: string[] };
    };
    added?: string[];
    removed?: string[];
    modified?: Array<{ path: string; sizeDiff: number }>;
  } | null;
  fDiffLoading: boolean;
  fDiffFile1: File | null;
  fDiffFile2: File | null;
  fReportLoading: boolean;
  fDiffRef1: React.RefObject<HTMLInputElement | null>;
  fDiffRef2: React.RefObject<HTMLInputElement | null>;
  totalFilesLabel: string;
  TNode: React.ComponentType<{
    node: FileTreeNode;
    onSelect: (node: FileTreeNode) => void;
    sel: string;
    filter?: string;
    mods?: Set<string>;
  }>;
  lang: (ext: string) => string;
  registerSmaliLanguage: (monaco: unknown) => void;
  fmtB: (bytes: number) => string;
  doSharedNodeSelect: (node: FileTreeNode, target: "intel" | "forensics") => void | Promise<void>;
  doDecodeStrings: () => void | Promise<void>;
  doXref: () => void | Promise<void>;
  doHierarchy: () => void | Promise<void>;
  doDataFlow: () => void | Promise<void>;
  doMethodSearch: () => void | Promise<void>;
  doDiff: () => void | Promise<void>;
  doForensicReport: () => void | Promise<void>;
  setForensicsTreeFilter: React.Dispatch<React.SetStateAction<string>>;
  setForensicsSelNode: React.Dispatch<React.SetStateAction<FileTreeNode | null>>;
  setForensicsSelContent: React.Dispatch<React.SetStateAction<string>>;
  setFPanel: React.Dispatch<React.SetStateAction<ForensicsPanel>>;
  setFXrefQuery: React.Dispatch<React.SetStateAction<string>>;
  setFMethodQuery: React.Dispatch<React.SetStateAction<string>>;
  setFDiffFile1: React.Dispatch<React.SetStateAction<File | null>>;
  setFDiffFile2: React.Dispatch<React.SetStateAction<File | null>>;
}

export function ForensicsTab(props: ForensicsTabProps) {
  const {
    sharedTree,
    forensicsTreeFilter,
    forensicsSelNode,
    forensicsSelContent,
    iSess,
    aFile,
    eFile,
    fPanel,
    fDecoded,
    fDecodedLoading,
    fXref,
    fXrefLoading,
    fXrefQuery,
    fHierarchy,
    fHierarchyLoading,
    fDataFlow,
    fDataFlowLoading,
    fMethodSearch,
    fMethodLoading,
    fMethodQuery,
    fDiff,
    fDiffLoading,
    fDiffFile1,
    fDiffFile2,
    fReportLoading,
    fDiffRef1,
    fDiffRef2,
    totalFilesLabel,
    TNode,
    lang,
    registerSmaliLanguage,
    fmtB,
    doSharedNodeSelect,
    doDecodeStrings,
    doXref,
    doHierarchy,
    doDataFlow,
    doMethodSearch,
    doDiff,
    doForensicReport,
    setForensicsTreeFilter,
    setForensicsSelNode,
    setForensicsSelContent,
    setFPanel,
    setFXrefQuery,
    setFMethodQuery,
    setFDiffFile1,
    setFDiffFile2,
  } = props;

  return (
    <div className="flex-1 grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-4 min-h-0">
      <div className="bg-card/70 backdrop-blur-sm border border-violet-500/20 rounded-2xl overflow-hidden flex flex-col">
        <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border bg-violet-500/5"><FolderOpen className="w-4 h-4 text-violet-400"/><span className="text-sm font-medium">الملفات</span>{sharedTree.length > 0 && <span className="mr-auto text-xs text-muted-foreground">{totalFilesLabel}</span>}</div>
        {sharedTree.length > 0 && <div className="px-2 pt-2 pb-1 border-b border-border/50"><div className="flex items-center gap-1.5 bg-muted/30 border border-border rounded-lg px-2 py-1"><Search className="w-3 h-3 text-muted-foreground shrink-0"/><input value={forensicsTreeFilter} onChange={e => setForensicsTreeFilter(e.target.value)} placeholder="بحث..." className="flex-1 bg-transparent text-xs outline-none text-right placeholder:text-muted-foreground/50 min-w-0"/>{forensicsTreeFilter && <button onClick={() => setForensicsTreeFilter("")} className="shrink-0"><X className="w-3 h-3 text-muted-foreground hover:text-foreground"/></button>}</div></div>}
        <div className="flex-1 overflow-y-auto p-1">{sharedTree.length === 0 ? <div className="flex flex-col items-center justify-center h-full py-8 text-muted-foreground text-xs"><FolderOpen className="w-8 h-8 mb-2 opacity-20"/><p>فكّك ملفاً أولاً</p></div> : sharedTree.map((n, i) => <TNode key={i} node={n} onSelect={n2 => { void doSharedNodeSelect(n2, "forensics"); }} sel={forensicsSelNode?.path || ""} filter={forensicsTreeFilter}/>)}</div>
      </div>

      <div className="flex flex-col gap-4 min-h-0 overflow-y-auto">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-gradient-to-br from-violet-500/20 to-pink-500/20 border border-violet-500/20"><Microscope className="w-5 h-5 text-violet-400"/></div>
          <div><h2 className="text-lg font-bold">مختبر الطب الشرعي</h2><p className="text-xs text-muted-foreground">تحليل متقدم · فك تشفير · تتبع مراجع · هرمية الكلاسات · تدفق البيانات</p></div>
          <Button onClick={() => { void doForensicReport(); }} disabled={fReportLoading || !iSess} size="sm" className="mr-auto gap-2 bg-violet-600 hover:bg-violet-700">{fReportLoading ? <Loader2 className="w-4 h-4 animate-spin"/> : <FileOutput className="w-4 h-4"/>}تصدير تقرير</Button>
        </div>

        {iSess && <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-xs">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0"/>
          <span className="text-emerald-300 font-medium">ملف محمّل</span>
          {aFile && <span className="text-muted-foreground truncate max-w-[200px]">{aFile.name}</span>}
          {eFile && !aFile && <span className="text-muted-foreground truncate max-w-[200px]">{eFile.name}</span>}
          <span className="text-muted-foreground/50 font-mono mr-auto">{iSess.slice(0, 8)}…</span>
          <Button onClick={async () => { toast.info("تحليل تلقائي..."); await doDecodeStrings(); void doHierarchy(); }} disabled={fDecodedLoading || fHierarchyLoading} size="sm" variant="outline" className="gap-1 h-7 text-[10px] border-violet-500/30 text-violet-300">{fDecodedLoading || fHierarchyLoading ? <Loader2 className="w-3 h-3 animate-spin"/> : <Zap className="w-3 h-3"/>}تحليل تلقائي</Button>
        </div>}
        {!iSess && <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-6 text-center text-sm text-amber-300"><AlertTriangle className="w-6 h-6 mx-auto mb-2"/>افتح ملفاً في التحليل أو التحرير أولاً لتفعيل أدوات الطب الشرعي</div>}
        {forensicsSelNode && <div className="bg-card/70 backdrop-blur-sm border border-violet-500/30 rounded-xl overflow-hidden" style={{ maxHeight: "300px" }}>
          <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-muted/20"><FileCode2 className="w-4 h-4 text-violet-400"/><span className="text-sm font-medium truncate">{forensicsSelNode.name}</span><button onClick={() => { setForensicsSelNode(null); setForensicsSelContent(""); }} className="mr-auto"><X className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground"/></button></div>
          <Editor height="250px" language={lang("." + forensicsSelNode.name.split(".").pop())} value={forensicsSelContent} theme={forensicsSelNode.name.endsWith(".smali") ? "smali-dark" : "vs-dark"} beforeMount={registerSmaliLanguage} options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12, lineNumbers: "on", scrollBeyondLastLine: false }}/>
        </div>}

        <div className="flex gap-1.5 flex-wrap">
          {([
            { id: "decode" as const, label: "فك التشفير", icon: Hash, color: "text-emerald-400 border-emerald-500/30" },
            { id: "xref" as const, label: "مراجع متقاطعة", icon: Link2, color: "text-cyan-400 border-cyan-500/30" },
            { id: "hierarchy" as const, label: "شجرة الوراثة", icon: Layers, color: "text-blue-400 border-blue-500/30" },
            { id: "dataflow" as const, label: "تدفق البيانات", icon: Network, color: "text-orange-400 border-orange-500/30" },
            { id: "methods" as const, label: "بحث التوقيعات", icon: Braces, color: "text-purple-400 border-purple-500/30" },
            { id: "diff" as const, label: "مقارنة APK", icon: Diff, color: "text-pink-400 border-pink-500/30" },
          ] as const).map(t => <button key={t.id} onClick={() => setFPanel(t.id)} className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium border transition-all ${fPanel === t.id ? `bg-card shadow ${t.color}` : "border-border text-muted-foreground hover:text-foreground hover:bg-muted/20"}`}><t.icon className="w-3.5 h-3.5"/>{t.label}</button>)}
        </div>

        {fPanel === "decode" && <div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 flex-1"><Hash className="w-4 h-4 text-emerald-400"/><span className="text-sm font-semibold">كشف وفك النصوص المشفرة</span><span className="text-[10px] text-muted-foreground">Base64 · Hex · URL · Unicode</span></div>
            <Button onClick={() => { void doDecodeStrings(); }} disabled={fDecodedLoading || !iSess} size="sm" className="gap-2">{fDecodedLoading ? <Loader2 className="w-4 h-4 animate-spin"/> : <Search className="w-4 h-4"/>}فحص</Button>
          </div>
          {fDecoded.length > 0 && <div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl divide-y divide-border/30">
            <div className="px-3 py-2 bg-muted/20 flex items-center gap-2 text-xs font-semibold sticky top-0 z-10"><span className="text-emerald-400">{fDecoded.length}</span> نص مكشوف</div>
            {fDecoded.map((d, i) => <div key={i} className="px-3 py-2 hover:bg-muted/10 space-y-1">
              <div className="flex items-center gap-2 text-xs"><span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${d.encoding === "base64" ? "bg-emerald-500/20 text-emerald-300" : d.encoding === "hex" ? "bg-orange-500/20 text-orange-300" : d.encoding === "url" ? "bg-blue-500/20 text-blue-300" : "bg-purple-500/20 text-purple-300"}`}>{d.encoding.toUpperCase()}</span><span className="text-muted-foreground font-mono truncate max-w-[200px]">{d.file}</span><span className="text-muted-foreground/50">:{d.line}</span><span className="mr-auto text-[10px] text-muted-foreground">{d.confidence}%</span></div>
              <div className="font-mono text-[11px] text-muted-foreground/60 truncate">{d.original}</div>
              <div className="font-mono text-[11px] text-emerald-300 truncate">→ {d.decoded}</div>
            </div>)}
          </div>}
        </div>}

        {fPanel === "xref" && <div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-2">
            <Link2 className="w-4 h-4 text-cyan-400"/>
            <span className="text-sm font-semibold">مراجع متقاطعة (Xref)</span>
          </div>
          <div className="flex gap-2"><input value={fXrefQuery} onChange={e => setFXrefQuery(e.target.value)} onKeyDown={e => e.key === "Enter" && void doXref()} placeholder="اسم كلاس أو ميثود مثل: MainActivity أو onClick" className="flex-1 bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm font-mono text-right" disabled={!iSess}/><Button onClick={() => { void doXref(); }} disabled={!iSess || fXrefLoading || !fXrefQuery.trim()}>{fXrefLoading ? <Loader2 className="w-4 h-4 animate-spin"/> : <Search className="w-4 h-4"/>}</Button></div>
          {fXref && <div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl">
            <div className="px-3 py-2 bg-muted/20 flex items-center gap-2 text-xs font-semibold sticky top-0 z-10 border-b border-border"><span className="text-cyan-400">{fXref.totalCount}</span> مرجع لـ <span className="font-mono text-cyan-300">{fXref.target}</span></div>
            <div className="divide-y divide-border/30 max-h-96 overflow-y-auto">{(fXref.references || []).map((r, i) => <div key={i} className="px-3 py-2 hover:bg-muted/10 space-y-0.5">
              <div className="flex items-center gap-2 text-xs"><span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${r.type === "invoke" ? "bg-blue-500/20 text-blue-300" : r.type === "field" ? "bg-orange-500/20 text-orange-300" : r.type === "type" ? "bg-purple-500/20 text-purple-300" : "bg-muted/30 text-muted-foreground"}`}>{r.type}</span><span className="font-mono text-muted-foreground truncate">{r.file}</span><span className="text-muted-foreground/50">:{r.line}</span></div>
              <div className="font-mono text-[11px] text-muted-foreground/80 truncate">{r.context}</div>
            </div>)}</div>
          </div>}
        </div>}

        {fPanel === "hierarchy" && <div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 flex-1"><Layers className="w-4 h-4 text-blue-400"/><span className="text-sm font-semibold">شجرة الوراثة</span></div>
            <Button onClick={() => { void doHierarchy(); }} disabled={fHierarchyLoading || !iSess} size="sm" className="gap-2">{fHierarchyLoading ? <Loader2 className="w-4 h-4 animate-spin"/> : <Layers className="w-4 h-4"/>}تحليل</Button>
          </div>
          {fHierarchy && <>
            <div className="grid grid-cols-4 gap-3">
              {([
                ["كلاسات", fHierarchy.stats.totalClasses, "text-blue-400 bg-blue-500/10 border-blue-500/30"],
                ["واجهات", fHierarchy.stats.interfaces, "text-purple-400 bg-purple-500/10 border-purple-500/30"],
                ["مجردة", fHierarchy.stats.abstractClasses, "text-orange-400 bg-orange-500/10 border-orange-500/30"],
                ["أقصى عمق", fHierarchy.stats.maxDepth, "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"],
              ] as const).map(([l, v, cls]) => <div key={l} className={`p-3 rounded-xl border text-center ${cls}`}><div className="text-2xl font-bold">{v}</div><div className="text-xs">{l}</div></div>)}
            </div>
            <div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl">
              <div className="px-3 py-2 bg-muted/20 text-xs font-semibold sticky top-0 z-10 border-b border-border">أهم الكلاسات (بعدد الأبناء)</div>
              <div className="divide-y divide-border/30 max-h-96 overflow-y-auto">{(fHierarchy.classes || []).filter(c => c.children.length > 0).sort((a, b) => b.children.length - a.children.length).slice(0, 100).map((c, i) => <div key={i} className="px-3 py-2 hover:bg-muted/10">
                <div className="flex items-center gap-2 text-xs"><span className={`w-2 h-2 rounded-full ${c.isInterface ? "bg-purple-400" : c.isAbstract ? "bg-orange-400" : "bg-blue-400"}`}/><span className="font-mono text-foreground truncate">{c.name}</span><span className="mr-auto text-muted-foreground">{c.children.length} ابن · {c.methods} ميثود · {c.fields} حقل</span></div>
                <div className="text-[10px] text-muted-foreground/60 font-mono mt-0.5 truncate">↑ {c.superClass}</div>
              </div>)}</div>
            </div>
          </>}
        </div>}

        {fPanel === "dataflow" && <div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 flex-1"><Network className="w-4 h-4 text-orange-400"/><span className="text-sm font-semibold">تحليل تدفق البيانات</span><span className="text-[10px] text-muted-foreground">تتبع APIs الحساسة · Sources · Sinks</span></div>
            <Button onClick={() => { void doDataFlow(); }} disabled={fDataFlowLoading || !iSess} size="sm" className="gap-2">{fDataFlowLoading ? <Loader2 className="w-4 h-4 animate-spin"/> : <Network className="w-4 h-4"/>}تحليل</Button>
          </div>
          {fDataFlow && <>
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 rounded-xl border text-center bg-red-500/10 border-red-500/30 text-red-400"><div className="text-2xl font-bold">{fDataFlow.sensitiveApis?.length || 0}</div><div className="text-xs">APIs حساسة</div></div>
              <div className="p-3 rounded-xl border text-center bg-orange-500/10 border-orange-500/30 text-orange-400"><div className="text-2xl font-bold">{fDataFlow.sinks?.length || 0}</div><div className="text-xs">Sinks</div></div>
              <div className="p-3 rounded-xl border text-center bg-blue-500/10 border-blue-500/30 text-blue-400"><div className="text-2xl font-bold">{fDataFlow.sources?.length || 0}</div><div className="text-xs">Sources</div></div>
            </div>
            {fDataFlow.sensitiveApis?.length > 0 && <div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl">
              <div className="px-3 py-2 bg-muted/20 text-xs font-semibold sticky top-0 z-10 border-b border-border">APIs حساسة مكتشفة</div>
              <div className="divide-y divide-border/30 max-h-96 overflow-y-auto">{fDataFlow.sensitiveApis.map((a, i) => <div key={i} className="px-3 py-2 hover:bg-muted/10 space-y-1">
                <div className="flex items-center gap-2 text-xs"><span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${a.category === "crypto" ? "bg-yellow-500/20 text-yellow-300" : a.category === "network" ? "bg-blue-500/20 text-blue-300" : a.category === "sms" ? "bg-red-500/20 text-red-300" : a.category === "location" ? "bg-green-500/20 text-green-300" : "bg-muted/30 text-muted-foreground"}`}>{a.category}</span><span className="font-semibold text-foreground">{a.api}</span><span className="mr-auto font-mono text-muted-foreground truncate max-w-[200px]">{a.file}:{a.line}</span></div>
                <div className="font-mono text-[11px] text-muted-foreground/70 truncate">{a.context}</div>
                {a.dataFlow && a.dataFlow.length > 0 && <div className="bg-black/20 rounded p-1.5 space-y-0.5">{a.dataFlow.map((l, j) => <div key={j} className="font-mono text-[10px] text-muted-foreground/60 truncate">{l}</div>)}</div>}
              </div>)}</div>
            </div>}
          </>}
        </div>}

        {fPanel === "methods" && <div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-2"><Braces className="w-4 h-4 text-purple-400"/><span className="text-sm font-semibold">بحث التوقيعات</span></div>
          <div className="flex gap-2"><input value={fMethodQuery} onChange={e => setFMethodQuery(e.target.value)} onKeyDown={e => e.key === "Enter" && void doMethodSearch()} placeholder="اسم ميثود مثل: onCreate, checkLicense, isPremium" className="flex-1 bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm font-mono text-right" disabled={!iSess}/><Button onClick={() => { void doMethodSearch(); }} disabled={!iSess || fMethodLoading || !fMethodQuery.trim()}>{fMethodLoading ? <Loader2 className="w-4 h-4 animate-spin"/> : <Search className="w-4 h-4"/>}</Button></div>
          <div className="flex gap-1.5 flex-wrap">{["onCreate", "onClick", "isPremium", "checkLicense", "decrypt", "verify", "init", "onReceive", "sendSMS", "getDeviceId"].map(q => <button key={q} onClick={() => { setFMethodQuery(q); }} className="text-[10px] px-2 py-1 rounded-full bg-muted/30 border border-border text-muted-foreground hover:text-foreground hover:bg-purple-500/10 hover:border-purple-500/30 transition-all">{q}</button>)}</div>
          {fMethodSearch && <div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl">
            <div className="px-3 py-2 bg-muted/20 text-xs font-semibold sticky top-0 z-10 border-b border-border"><span className="text-purple-400">{fMethodSearch.totalFound}</span> ميثود</div>
            <div className="divide-y divide-border/30 max-h-96 overflow-y-auto">{(fMethodSearch.methods || []).map((m, i) => <div key={i} className="px-3 py-2 hover:bg-muted/10 space-y-0.5">
              <div className="flex items-center gap-2 text-xs"><span className="text-purple-300 font-semibold">{m.methodName}</span><span className="font-mono text-muted-foreground/60 truncate">{m.signature}</span></div>
              <div className="flex items-center gap-2 text-[10px] text-muted-foreground"><span className="font-mono truncate max-w-[250px]">{m.file}:{m.line}</span><span>·</span><span>{m.linesOfCode} سطر</span><span>·</span><span>{m.registers} مسجل</span><span className="mr-auto text-muted-foreground/50">{m.modifiers}</span></div>
            </div>)}</div>
          </div>}
        </div>}

        {fPanel === "diff" && <div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-2"><Diff className="w-4 h-4 text-pink-400"/><span className="text-sm font-semibold">مقارنة ملفين</span><span className="text-[10px] text-muted-foreground">ارفع نسختين لمقارنة الفروقات</span></div>
          <div className="grid grid-cols-2 gap-3">
            <div className="border border-dashed border-border rounded-xl p-4 text-center cursor-pointer hover:border-pink-500/40 hover:bg-pink-500/5 transition-all" onClick={() => fDiffRef1.current?.click()}>
              <input ref={fDiffRef1} type="file" accept=".apk,.exe,.dll,.msi,.ex4,.ex5,.ipa,.jar,.aar,.dex,.so,.wasm" className="hidden" onChange={e => { if (e.target.files?.[0]) setFDiffFile1(e.target.files[0]); }}/>
              <Upload className="w-6 h-6 mx-auto mb-1 text-muted-foreground"/>
              <div className="text-xs font-semibold">{fDiffFile1 ? fDiffFile1.name : "النسخة القديمة"}</div>
              {fDiffFile1 && <div className="text-[10px] text-muted-foreground mt-1">{fmtB(fDiffFile1.size)}</div>}
            </div>
            <div className="border border-dashed border-border rounded-xl p-4 text-center cursor-pointer hover:border-pink-500/40 hover:bg-pink-500/5 transition-all" onClick={() => fDiffRef2.current?.click()}>
              <input ref={fDiffRef2} type="file" accept=".apk,.exe,.dll,.msi,.ex4,.ex5,.ipa,.jar,.aar,.dex,.so,.wasm" className="hidden" onChange={e => { if (e.target.files?.[0]) setFDiffFile2(e.target.files[0]); }}/>
              <Upload className="w-6 h-6 mx-auto mb-1 text-muted-foreground"/>
              <div className="text-xs font-semibold">{fDiffFile2 ? fDiffFile2.name : "النسخة الجديدة"}</div>
              {fDiffFile2 && <div className="text-[10px] text-muted-foreground mt-1">{fmtB(fDiffFile2.size)}</div>}
            </div>
          </div>
          <Button onClick={() => { void doDiff(); }} disabled={fDiffLoading || !fDiffFile1 || !fDiffFile2} className="gap-2 self-start">{fDiffLoading ? <Loader2 className="w-4 h-4 animate-spin"/> : <Diff className="w-4 h-4"/>}مقارنة</Button>
          {fDiff && <>
            <div className="grid grid-cols-4 gap-3">
              <div className="p-3 rounded-xl border text-center bg-emerald-500/10 border-emerald-500/30 text-emerald-400"><div className="text-2xl font-bold">{fDiff.summary?.totalAdded || 0}</div><div className="text-xs">مضافة</div></div>
              <div className="p-3 rounded-xl border text-center bg-red-500/10 border-red-500/30 text-red-400"><div className="text-2xl font-bold">{fDiff.summary?.totalRemoved || 0}</div><div className="text-xs">محذوفة</div></div>
              <div className="p-3 rounded-xl border text-center bg-yellow-500/10 border-yellow-500/30 text-yellow-400"><div className="text-2xl font-bold">{fDiff.summary?.totalModified || 0}</div><div className="text-xs">معدّلة</div></div>
              <div className="p-3 rounded-xl border text-center bg-muted/20 border-border text-muted-foreground"><div className="text-2xl font-bold">{fDiff.summary?.totalUnchanged || 0}</div><div className="text-xs">بدون تغيير</div></div>
            </div>
            {fDiff.summary?.versionChange && <div className="text-xs text-muted-foreground bg-muted/20 rounded-lg px-3 py-2">الإصدار: <span className="text-red-400">{fDiff.summary.versionChange.old}</span> → <span className="text-emerald-400">{fDiff.summary.versionChange.new}</span></div>}
            {(fDiff.summary?.permissionChanges?.added?.length || 0) > 0 || (fDiff.summary?.permissionChanges?.removed?.length || 0) > 0 ? <div className="bg-card/70 border border-border rounded-xl p-3 space-y-1">
              <div className="text-xs font-semibold">تغييرات الأذونات</div>
              {fDiff.summary?.permissionChanges?.added?.map((p, i) => <div key={"a" + i} className="text-[11px] font-mono text-emerald-400">+ {p}</div>)}
              {fDiff.summary?.permissionChanges?.removed?.map((p, i) => <div key={"r" + i} className="text-[11px] font-mono text-red-400">- {p}</div>)}
            </div> : null}
            <div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl">
              <div className="divide-y divide-border/30 max-h-64 overflow-y-auto">
                {fDiff.added?.slice(0, 50).map((f, i) => <div key={"a" + i} className="px-3 py-1.5 text-xs font-mono text-emerald-400 hover:bg-muted/10">+ {f}</div>)}
                {fDiff.removed?.slice(0, 50).map((f, i) => <div key={"r" + i} className="px-3 py-1.5 text-xs font-mono text-red-400 hover:bg-muted/10">- {f}</div>)}
                {fDiff.modified?.slice(0, 50).map((f, i) => <div key={"m" + i} className="px-3 py-1.5 text-xs font-mono text-yellow-400 hover:bg-muted/10 flex items-center gap-2">~ {f.path} <span className="mr-auto text-muted-foreground">{f.sizeDiff > 0 ? "+" : ""}{fmtB(Math.abs(f.sizeDiff))}</span></div>)}
              </div>
            </div>
          </>}
        </div>}
      </div>
    </div>
  );
}
