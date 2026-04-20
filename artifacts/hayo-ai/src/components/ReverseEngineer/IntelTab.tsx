import type React from "react";
import Editor from "@monaco-editor/react";
import { Button } from "@/components/ui/button";
import {
  AlertTriangle,
  CheckCircle2,
  FileCode2,
  Fingerprint,
  FolderOpen,
  Globe,
  Key,
  Loader2,
  Lock,
  Scan,
  Search,
  Terminal,
  X,
} from "lucide-react";
import type { FileTreeNode, IntelReport, VulnerabilityFinding } from "./types";

interface IntelTabProps {
  sharedTree: FileTreeNode[];
  intelTreeFilter: string;
  intelSelNode: FileTreeNode | null;
  intelSelContent: string;
  intel: IntelReport | null;
  intelLoading: boolean;
  irPat: string;
  irRes: Array<{ filePath: string; line: number; match: string; context: string }>;
  irSearching: boolean;
  irCat: string;
  iSess: string;
  aFile: File | null;
  eFile: File | null;
  vulnerabilities?: VulnerabilityFinding[];
  totalFilesLabel: string;
  TNode: React.ComponentType<{
    node: FileTreeNode;
    onSelect: (node: FileTreeNode) => void;
    sel: string;
    filter?: string;
    mods?: Set<string>;
  }>;
  ThreatGauge: React.ComponentType<{ vulns: VulnerabilityFinding[] | undefined }>;
  VulnChart: React.ComponentType<{ vulns: VulnerabilityFinding[] | undefined }>;
  lang: (ext: string) => string;
  registerSmaliLanguage: (monaco: unknown) => void;
  doSharedNodeSelect: (node: FileTreeNode, target: "intel" | "forensics") => void | Promise<void>;
  doIntel: () => void | Promise<void>;
  doRegex: (pattern?: string, category?: string) => void | Promise<void>;
  setIntelTreeFilter: React.Dispatch<React.SetStateAction<string>>;
  setIntelSelNode: React.Dispatch<React.SetStateAction<FileTreeNode | null>>;
  setIntelSelContent: React.Dispatch<React.SetStateAction<string>>;
  setIrPat: React.Dispatch<React.SetStateAction<string>>;
  setIrCat: React.Dispatch<React.SetStateAction<string>>;
}

export function IntelTab(props: IntelTabProps) {
  const {
    sharedTree,
    intelTreeFilter,
    intelSelNode,
    intelSelContent,
    intel,
    intelLoading,
    irPat,
    irRes,
    irSearching,
    irCat,
    iSess,
    aFile,
    eFile,
    vulnerabilities,
    totalFilesLabel,
    TNode,
    ThreatGauge,
    VulnChart,
    lang,
    registerSmaliLanguage,
    doSharedNodeSelect,
    doIntel,
    doRegex,
    setIntelTreeFilter,
    setIntelSelNode,
    setIntelSelContent,
    setIrPat,
    setIrCat,
  } = props;

  return (
    <div className="flex-1 grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-4 min-h-0">
      <div className="bg-card/70 backdrop-blur-sm border border-cyan-500/20 rounded-2xl overflow-hidden flex flex-col">
        <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border bg-cyan-500/5"><FolderOpen className="w-4 h-4 text-cyan-400"/><span className="text-sm font-medium">الملفات</span>{sharedTree.length > 0 && <span className="mr-auto text-xs text-muted-foreground">{totalFilesLabel}</span>}</div>
        {sharedTree.length > 0 && <div className="px-2 pt-2 pb-1 border-b border-border/50"><div className="flex items-center gap-1.5 bg-muted/30 border border-border rounded-lg px-2 py-1"><Search className="w-3 h-3 text-muted-foreground shrink-0"/><input value={intelTreeFilter} onChange={e => setIntelTreeFilter(e.target.value)} placeholder="بحث..." className="flex-1 bg-transparent text-xs outline-none text-right placeholder:text-muted-foreground/50 min-w-0"/>{intelTreeFilter && <button onClick={() => setIntelTreeFilter("")} className="shrink-0"><X className="w-3 h-3 text-muted-foreground hover:text-foreground"/></button>}</div></div>}
        <div className="flex-1 overflow-y-auto p-1">{sharedTree.length === 0 ? <div className="flex flex-col items-center justify-center h-full py-8 text-muted-foreground text-xs"><FolderOpen className="w-8 h-8 mb-2 opacity-20"/><p>فكّك ملفاً أولاً</p></div> : sharedTree.map((n, i) => <TNode key={i} node={n} onSelect={n2 => { void doSharedNodeSelect(n2, "intel"); }} sel={intelSelNode?.path || ""} filter={intelTreeFilter}/>)}</div>
      </div>

      <div className="flex flex-col gap-4 min-h-0 overflow-y-auto">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/20"><Fingerprint className="w-5 h-5 text-cyan-400"/></div>
          <div><h2 className="text-lg font-bold">لوحة الاستخبارات</h2><p className="text-xs text-muted-foreground">APIs · URLs · مفاتيح · تشفير · بيانات حساسة</p></div>
          <Button onClick={() => { void doIntel(); }} disabled={intelLoading || !iSess} size="sm" className="mr-auto gap-2 bg-cyan-600 hover:bg-cyan-700">{intelLoading ? <Loader2 className="w-4 h-4 animate-spin"/> : <Scan className="w-4 h-4"/>}فحص</Button>
        </div>

        {iSess && <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-xs">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0"/>
          <span className="text-emerald-300 font-medium">ملف محمّل</span>
          {aFile && <span className="text-muted-foreground truncate max-w-[200px]">{aFile.name}</span>}
          {eFile && !aFile && <span className="text-muted-foreground truncate max-w-[200px]">{eFile.name}</span>}
          <span className="text-muted-foreground/50 font-mono mr-auto">{iSess.slice(0, 8)}…</span>
        </div>}
        {!iSess && <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-4 text-center text-sm text-amber-300"><AlertTriangle className="w-5 h-5 mx-auto mb-2"/>افتح ملفاً في التحليل أو التحرير أولاً</div>}

        {intelSelNode && <div className="bg-card/70 backdrop-blur-sm border border-cyan-500/30 rounded-xl overflow-hidden" style={{ maxHeight: "300px" }}>
          <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-muted/20"><FileCode2 className="w-4 h-4 text-cyan-400"/><span className="text-sm font-medium truncate">{intelSelNode.name}</span><button onClick={() => { setIntelSelNode(null); setIntelSelContent(""); }} className="mr-auto"><X className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground"/></button></div>
          <Editor height="250px" language={lang("." + intelSelNode.name.split(".").pop())} value={intelSelContent} theme={intelSelNode.name.endsWith(".smali") ? "smali-dark" : "vs-dark"} beforeMount={registerSmaliLanguage} options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12, lineNumbers: "on", scrollBeyondLastLine: false }}/>
        </div>}

        {(vulnerabilities || intel) && <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <ThreatGauge vulns={vulnerabilities}/>
          <VulnChart vulns={vulnerabilities}/>
        </div>}

        {intel && <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {([
            ["ssl", "SSL/TLS", Lock, "text-red-400 bg-red-500/10 border-red-500/30"],
            ["root", "Root", Terminal, "text-orange-400 bg-orange-500/10 border-orange-500/30"],
            ["crypto", "Crypto", Key, "text-yellow-400 bg-yellow-500/10 border-yellow-500/30"],
            ["secrets", "Secrets", Fingerprint, "text-purple-400 bg-purple-500/10 border-purple-500/30"],
            ["urls", "URLs", Globe, "text-blue-400 bg-blue-500/10 border-blue-500/30"],
          ] as const).map(([k, l, Ic, cls]) => <button key={k} onClick={() => { setIrCat(k); void doRegex("", k); }} className={`p-3 rounded-xl border transition-all hover:scale-105 ${cls}`}><Ic className="w-5 h-5 mx-auto mb-1"/><div className="text-2xl font-bold">{intel[k as keyof IntelReport]?.length || 0}</div><div className="text-xs font-medium">{l}</div></button>)}
        </div>}

        <div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-3 space-y-2">
          <div className="flex items-center gap-2"><Search className="w-4 h-4 text-cyan-400"/><span className="text-sm font-semibold">بحث Regex</span></div>
          <div className="flex gap-2"><input value={irPat} onChange={e => setIrPat(e.target.value)} onKeyDown={e => e.key === "Enter" && void doRegex()} placeholder="api[_-]?key|password" className="flex-1 bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm font-mono text-right placeholder:text-muted-foreground/50" disabled={!iSess || irSearching}/><Button onClick={() => { void doRegex(); }} disabled={!iSess || irSearching || !irPat.trim()}>{irSearching ? <Loader2 className="w-4 h-4 animate-spin"/> : <Search className="w-4 h-4"/>}</Button></div>
          <div className="flex flex-wrap gap-1.5">{["SSL", "Root", "Crypto", "Secrets", "URLs"].map(c => <button key={c} onClick={() => { setIrCat(c.toLowerCase()); void doRegex("", c.toLowerCase()); }} className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${irCat === c.toLowerCase() ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-300" : "bg-muted/30 border-border text-muted-foreground hover:text-foreground"}`}>{c}</button>)}</div>
        </div>

        {irRes.length > 0 && <div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl overflow-hidden">
          <div className="px-3 py-2 border-b border-border bg-muted/20 flex items-center gap-2"><Terminal className="w-3.5 h-3.5 text-cyan-400"/><span className="text-xs font-semibold">{irRes.length} نتيجة</span></div>
          <div className="max-h-96 overflow-y-auto divide-y divide-border/50">{irRes.map((r, i) => <div key={i} className="px-3 py-2 hover:bg-muted/10"><div className="flex items-center gap-2 text-xs"><span className="text-cyan-400 font-mono truncate max-w-[200px]">{r.filePath}</span><span className="text-muted-foreground">:{r.line}</span><span className="mr-auto text-emerald-400 font-medium">{r.match}</span></div><div className="text-[11px] font-mono text-muted-foreground mt-0.5 truncate">{r.context}</div></div>)}</div>
        </div>}

        {intel && irCat && (intel[irCat as keyof IntelReport] as string[])?.length > 0 && <div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-3 space-y-2 max-h-64 overflow-y-auto"><div className="text-sm font-semibold">{irCat.toUpperCase()}</div>{(intel[irCat as keyof IntelReport] as string[]).map((item, i) => <div key={i} className="text-xs font-mono bg-muted/20 rounded px-2 py-1 truncate text-muted-foreground">{item}</div>)}</div>}
      </div>
    </div>
  );
}
