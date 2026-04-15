/*
 * HAYO AI — RE:PLATFORM v4.0
 * Tab 1: تحليل  Tab 2: استنساخ  Tab 3: تحرير & بناء  Tab 4: استخبارات  Tab 5: طب شرعي
 * Formats: APK·EXE·DLL·MSI·EX4/5·IPA·JAR·AAR·DEX·SO·WASM
 */
import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import Editor from "@monaco-editor/react";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  Upload, FileCode2, FolderOpen, ChevronRight, ChevronDown,
  Download, Bot, Copy, Loader2, X, CheckCircle2,
  Info, Lock, Unlock, ScanSearch, Package, Cpu, Shield, Fingerprint, Microscope,
  Wrench, Archive, FileJson,
  Search, Save, Hammer, Binary, AlertTriangle,
  Dot, CheckCheck, Undo2, Sparkles, Eye, Zap,
  GitBranch,
  Keyboard, Database, Activity, TrendingUp, BarChart3, Code,
  ArrowUpDown, type LucideIcon,
} from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import CloneTab from "@/components/ReverseEngineer/CloneTab";
import { AnalysisTab } from "@/components/ReverseEngineer/AnalysisTab";
import { IntelTab } from "@/components/ReverseEngineer/IntelTab";
import { ForensicsTab } from "@/components/ReverseEngineer/ForensicsTab";
import { CloudPentestTab } from "@/components/ReverseEngineer/CloudPentestTab";
import type {
  CloneResult,
  CloneOptions,
  DecompileResult as SharedDecompileResult,
  DecompiledFile as SharedDecompiledFile,
  EditSession as SharedEditSession,
  FileTreeNode as SharedFileTreeNode,
  IntelReport as SharedIntelReport,
  LiveStreamState,
  SmartModifyResult as SharedSmartModifyResult,
  VulnerabilityFinding as SharedVulnerabilityFinding,
} from "@/components/ReverseEngineer/types";

// ═══ Types ═══
type DecompiledFile = SharedDecompiledFile;
type FileTreeNode = SharedFileTreeNode;
type VulnerabilityFinding = SharedVulnerabilityFinding;
type DecompileResult = SharedDecompileResult;
type EditSession = SharedEditSession;
type IntelReport = SharedIntelReport;
type SmartModifyResult = SharedSmartModifyResult;

// ═══ Constants ═══
const ALL_FORMATS = ["apk","exe","dll","msi","ex4","ex5","ipa","jar","aar","dex","so","wasm"] as const;
const ACCEPT_STR = ALL_FORMATS.map(f=>`.${f}`).join(",");
const FMT_ICON:Record<string,string> = {apk:"🤖",exe:"🖥️",dll:"⚙️",msi:"📦",ex4:"📈",ex5:"📊",ipa:"🍎",jar:"☕",aar:"🟢",dex:"🔵",so:"🔧",wasm:"🌐"};
const FMT_LABEL:Record<string,string> = {apk:"Android APK",exe:"Windows EXE",dll:"Windows DLL",msi:"Windows MSI",ex4:"MetaTrader 4",ex5:"MetaTrader 5",ipa:"iOS IPA",jar:"Java JAR",aar:"Android AAR",dex:"Dalvik DEX",so:"Linux SO/ELF",wasm:"WebAssembly"};
const DANGER_PERMS = new Set(["READ_CONTACTS","WRITE_CONTACTS","READ_SMS","SEND_SMS","READ_PHONE_STATE","CALL_PHONE","ACCESS_FINE_LOCATION","CAMERA","RECORD_AUDIO","READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE","USE_BIOMETRIC"]);

const LiveTerminal = ({ sseUrl, onComplete, onResult }: { sseUrl: string; onComplete?: () => void; onResult?: (data: any) => void }) => {
  const [logs, setLogs] = useState<string[]>([]);
  const [done, setDone] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setLogs([]);setDone(false);
    const eventSource = new EventSource(sseUrl);
    eventSource.addEventListener("result", (e: any) => {
      try { if (onResult) onResult(JSON.parse(e.data)); } catch {}
    });
    eventSource.onmessage = (e) => {
      setLogs(prev => [...prev, e.data]);
      if (e.data.startsWith("[DONE]") || e.data.startsWith("[ERROR]")) {
        setDone(true);
        eventSource.close();
        if (onComplete) onComplete();
      }
    };
    eventSource.onerror = () => { eventSource.close(); setLogs(prev => [...prev, "[ERROR] انقطع الاتصال"]); setDone(true); };
    return () => eventSource.close();
  }, [sseUrl]);
  useEffect(() => { scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight); }, [logs]);
  return (
    <div ref={scrollRef} className="bg-black text-green-400 font-mono text-xs p-4 rounded-xl h-[300px] overflow-y-auto border border-zinc-800 shadow-inner">
      {logs.map((log, i) => (
        <div key={i} className={`whitespace-pre-wrap leading-relaxed ${log.includes("[STEP]")?"text-cyan-400 font-bold":log.includes("[WARN]")?"text-yellow-400":log.includes("[ERROR]")?"text-red-400":log.includes("[DONE]")?"text-cyan-400 font-bold":log.includes("[MOD]")?"text-purple-400":log.includes("[INFO]")?"text-blue-400":log.startsWith("$")?"text-white font-bold":""}`}>{log}</div>
      ))}
      {!done&&<div className="inline-block w-2 h-4 bg-green-400 animate-pulse ml-1"/>}
    </div>
  );
};

function fileIcon(ext:string){const m:Record<string,string>={".java":"☕",".kt":"🟣",".smali":"🔩",".js":"🟨",".ts":"🟦",".xml":"📄",".json":"📋",".swift":"🦅",".c":"©️",".cpp":"➕",".cs":"🟪",".html":"🌐",".css":"🎨",".mq4":"📈",".mq5":"📊",".plist":"🍎",".txt":"📝",".pro":"📌",".properties":"⚙️",".gradle":"🔨"};return m[ext]||"📄";}
function lang(ext:string){const m:Record<string,string>={".java":"java",".kt":"kotlin",".smali":"smali",".js":"javascript",".ts":"typescript",".xml":"xml",".json":"json",".html":"html",".css":"css",".swift":"swift",".c":"c",".cpp":"cpp",".cs":"csharp",".mq4":"cpp",".mq5":"cpp",".md":"markdown",".yml":"yaml",".yaml":"yaml",".properties":"ini",".gradle":"groovy"};return m[ext]||"plaintext";}
function fmtB(b:number){if(b<1024)return b+" B";if(b<1048576)return(b/1024).toFixed(1)+" KB";return(b/1048576).toFixed(1)+" MB";}

let smaliRegistered=false;
function registerSmaliLanguage(monaco:any){
  if(smaliRegistered)return;smaliRegistered=true;
  monaco.languages.register({id:"smali"});
  monaco.languages.setMonarchTokensProvider("smali",{
    tokenizer:{
      root:[
        [/^\s*#.*$/,"comment"],
        [/\.(class|super|source|implements|field|method|end method|end field|annotation|end annotation|subannotation|end subannotation|enum|registers|locals|param|prologue|line|catch|catchall)\b/,"keyword"],
        [/\b(invoke-virtual|invoke-super|invoke-direct|invoke-static|invoke-interface|invoke-virtual\/range|invoke-static\/range|invoke-direct\/range|invoke-interface\/range)\b/,"keyword.invoke"],
        [/\b(iget|iget-wide|iget-object|iget-boolean|iget-byte|iget-char|iget-short|iput|iput-wide|iput-object|iput-boolean|iput-byte|iput-char|iput-short|sget|sget-wide|sget-object|sget-boolean|sput|sput-wide|sput-object|sput-boolean)\b/,"keyword.field"],
        [/\b(move|move-wide|move-object|move-result|move-result-wide|move-result-object|move-exception|return-void|return|return-wide|return-object|const|const\/4|const\/16|const\/high16|const-wide|const-wide\/16|const-wide\/32|const-wide\/high16|const-string|const-string\/jumbo|const-class)\b/,"keyword.move"],
        [/\b(if-eq|if-ne|if-lt|if-ge|if-gt|if-le|if-eqz|if-nez|if-ltz|if-gez|if-gtz|if-lez|goto|goto\/16|goto\/32|packed-switch|sparse-switch)\b/,"keyword.control"],
        [/\b(new-instance|new-array|check-cast|instance-of|array-length|fill-new-array|filled-new-array|throw|monitor-enter|monitor-exit)\b/,"keyword.object"],
        [/\b(add-int|sub-int|mul-int|div-int|rem-int|and-int|or-int|xor-int|shl-int|shr-int|ushr-int|neg-int|not-int|add-long|sub-long|mul-long|div-long|add-float|sub-float|mul-float|div-float|add-double|sub-double|mul-double|div-double|int-to-long|int-to-float|int-to-double|long-to-int|float-to-int|double-to-int|int-to-byte|int-to-char|int-to-short|nop|cmp-long|cmpl-float|cmpg-float|cmpl-double|cmpg-double)\b/,"keyword.math"],
        [/\b(aget|aget-wide|aget-object|aget-boolean|aget-byte|aget-char|aget-short|aput|aput-wide|aput-object|aput-boolean|aput-byte|aput-char|aput-short)\b/,"keyword.array"],
        [/\b[vp]\d+\b/,"variable.register"],
        [/L[\w\/$]+;/,"type.class"],
        [/"[^"]*"/,"string"],
        [/->[\w<>]+/,"entity.method"],
        [/:\w+/,"tag.label"],
        [/0x[0-9a-fA-F]+\b/,"number.hex"],
        [/\b-?\d+\b/,"number"],
      ]
    }
  });
  monaco.editor.defineTheme("smali-dark",{
    base:"vs-dark",inherit:true,
    rules:[
      {token:"comment",foreground:"6A9955",fontStyle:"italic"},
      {token:"keyword",foreground:"C586C0",fontStyle:"bold"},
      {token:"keyword.invoke",foreground:"DCDCAA"},
      {token:"keyword.field",foreground:"9CDCFE"},
      {token:"keyword.move",foreground:"569CD6"},
      {token:"keyword.control",foreground:"D16969",fontStyle:"bold"},
      {token:"keyword.object",foreground:"4EC9B0"},
      {token:"keyword.math",foreground:"B5CEA8"},
      {token:"keyword.array",foreground:"CE9178"},
      {token:"variable.register",foreground:"F5C2E7",fontStyle:"bold"},
      {token:"type.class",foreground:"A6E3A1"},
      {token:"string",foreground:"CE9178"},
      {token:"entity.method",foreground:"74C7EC"},
      {token:"tag.label",foreground:"FFE66D"},
      {token:"number.hex",foreground:"B5CEA8"},
      {token:"number",foreground:"B5CEA8"},
    ],
    colors:{}
  });
}

async function fetchRE(url:string,opts:RequestInit={},timeoutMs=300000):Promise<Response>{
  const ctrl=new AbortController();
  const timer=setTimeout(()=>ctrl.abort(),timeoutMs);
  try{
    const r=await fetch(url,{...opts,credentials:"include",signal:ctrl.signal});
    return r;
  }catch(e:any){
    if(e.name==="AbortError") throw new Error("انتهت المهلة — الملف كبير أو الاتصال بطيء. جرّب إيقاف VPN أو استخدم ملف أصغر.");
    if(!navigator.onLine) throw new Error("لا يوجد اتصال بالإنترنت");
    throw new Error(e.message || "خطأ في الاتصال بالخادم");
  }finally{clearTimeout(timer);}
}

// ═══ Tree Node ═══
function treeMatch(node:FileTreeNode,f:string):boolean{
  if(!f)return true;
  const q=f.toLowerCase();
  if(node.name.toLowerCase().includes(q))return true;
  if(node.type==="folder"&&node.children)return node.children.some(c=>treeMatch(c,q));
  return false;
}
function TNode({node,onSelect,sel,mods,filter="",d=0}:{node:FileTreeNode;onSelect:(n:FileTreeNode)=>void;sel:string;mods?:Set<string>;filter?:string;d?:number}){
  if(!treeMatch(node,filter))return null;
  const ai=node.name==="ai-decompile";
  const forceOpen=filter.length>0;
  const[open,setOpen]=useState(d<2||ai);
  const isOpen=forceOpen||open;
  if(node.type==="folder") return(<div>
    <button onClick={()=>!forceOpen&&setOpen(e=>!e)} className={`flex items-center gap-1.5 w-full text-left px-2 py-1 rounded text-sm ${ai?"hover:bg-primary/10 text-primary/80":"hover:bg-white/5"}`} style={{paddingLeft:`${8+d*14}px`}}>
      {isOpen?<ChevronDown className="w-3.5 h-3.5 text-muted-foreground shrink-0"/>:<ChevronRight className="w-3.5 h-3.5 text-muted-foreground shrink-0"/>}
      {ai?<Sparkles className="w-3.5 h-3.5 text-primary shrink-0"/>:<FolderOpen className="w-3.5 h-3.5 text-amber-400/80 shrink-0"/>}
      <span className={ai?"text-primary font-medium truncate":"text-muted-foreground truncate"}>{node.name}</span>
    </button>
    {isOpen&&node.children?.map((c,i)=><TNode key={i} node={c} onSelect={onSelect} sel={sel} mods={mods} filter={filter} d={d+1}/>)}
  </div>);
  const ext="."+( node.name.split(".").pop()||"");
  const q=filter.toLowerCase();
  const hi=filter&&node.name.toLowerCase().includes(q);
  return(<button onClick={()=>onSelect(node)} className={`flex items-center gap-1.5 w-full text-left px-2 py-1 rounded text-xs ${node.path===sel?"bg-primary/20 text-primary":hi?"bg-emerald-500/10 text-emerald-300":"hover:bg-white/5 text-muted-foreground hover:text-foreground"}`} style={{paddingLeft:`${8+d*14}px`}}>
    <span className="shrink-0 w-4 text-center text-xs">{fileIcon(ext)}</span>
    <span className="truncate">{node.name}</span>
    {mods?.has(node.path)&&<Dot className="w-4 h-4 text-yellow-400 shrink-0 ml-auto"/>}
  </button>);
}

// ═══ Vuln Panel ═══
const SC:Record<string,string>={critical:"text-red-400 bg-red-500/10 border-red-500/30",high:"text-orange-400 bg-orange-500/10 border-orange-500/30",medium:"text-yellow-400 bg-yellow-500/10 border-yellow-500/30",low:"text-blue-400 bg-blue-500/10 border-blue-500/30",info:"text-muted-foreground bg-muted/20 border-border"};
const SL:Record<string,string>={critical:"حرج",high:"عالي",medium:"متوسط",low:"منخفض",info:"معلومة"};
function VPanel({findings}:{findings:VulnerabilityFinding[]}){
  const[exp,setExp]=useState<number|null>(null);
  const ct=findings.reduce((a,f)=>{a[f.severity]=(a[f.severity]||0)+1;return a;},{} as Record<string,number>);
  return(<div className={`bg-card/70 backdrop-blur-sm border rounded-xl p-3 space-y-2 ${ct.critical?"border-red-500/40":ct.high?"border-orange-500/30":"border-border"}`}>
    <div className="flex items-center gap-2"><Shield className={`w-4 h-4 ${ct.critical?"text-red-400":"text-muted-foreground"}`}/><span className="text-sm font-semibold">ثغرات</span><span className="mr-auto text-xs text-muted-foreground">{findings.length}</span></div>
    <div className="flex gap-1.5 flex-wrap">{(["critical","high","medium","low","info"] as const).map(s=>ct[s]?<span key={s} className={`text-[10px] px-2 py-0.5 rounded-full border ${SC[s]}`}>{SL[s]} ×{ct[s]}</span>:null)}</div>
    <div className="space-y-1 max-h-64 overflow-y-auto">{findings.map((f,i)=><div key={i} className={`border rounded-lg overflow-hidden ${SC[f.severity]}`}>
      <button className="w-full flex items-center gap-2 px-2.5 py-1.5 text-xs text-left" onClick={()=>setExp(exp===i?null:i)}><AlertTriangle className="w-3 h-3 shrink-0"/><span className="font-medium truncate flex-1">{f.title}</span><span className="text-[9px] opacity-60">{f.category}</span></button>
      {exp===i&&<div className="px-2.5 pb-2 text-[11px] space-y-1 border-t border-current/10"><p className="text-foreground/80 pt-1">{f.description}</p>{f.evidence.length>0&&<div className="font-mono bg-black/20 rounded p-1.5 max-h-24 overflow-y-auto">{f.evidence.map((e,j)=><div key={j} className="truncate opacity-80">{e}</div>)}</div>}</div>}
    </div>)}</div>
  </div>);
}

// ══════════════════════════════════════════════════════════════
// PROGRESS STEPS — shown during decompile
// ══════════════════════════════════════════════════════════════
const DECOMP_STEPS=["قراءة الملف","فك الضغط","تحليل البنية","تفكيك الكود","فحص أمني"];

function ProgressSteps({step}:{step:number}){
  const pct=Math.round((step/4)*100);
  return(
    <div className="bg-card/70 backdrop-blur-sm border border-emerald-500/30 rounded-2xl p-4 space-y-4 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex items-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin text-emerald-400"/>
        <span className="text-sm font-semibold text-emerald-300">جاري التفكيك...</span>
        <span className="mr-auto text-xs text-muted-foreground font-mono">{pct}%</span>
      </div>
      {/* Progress bar */}
      <div className="h-1.5 bg-muted/40 rounded-full overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-emerald-500 to-cyan-400 rounded-full transition-all duration-700 ease-out"
          style={{width:`${pct}%`}}
        />
      </div>
      {/* Step circles */}
      <div className="flex items-start justify-between gap-1">
        {DECOMP_STEPS.map((label,i)=>{
          const done=i<step;
          const active=i===step;
          return(
            <div key={i} className="flex flex-col items-center gap-1.5 flex-1">
              <div className={`w-7 h-7 rounded-full flex items-center justify-center border-2 transition-all duration-500 text-[10px] font-bold
                ${done?"bg-emerald-500 border-emerald-500 text-white scale-105"
                :active?"bg-emerald-500/20 border-emerald-400 text-emerald-300 animate-pulse"
                :"bg-muted/30 border-border text-muted-foreground"}`}>
                {done?<CheckCircle2 className="w-3.5 h-3.5"/>:i+1}
              </div>
              <span className={`text-[9px] text-center leading-tight transition-colors duration-300
                ${done?"text-emerald-400":active?"text-emerald-300 font-semibold":"text-muted-foreground/60"}`}>
                {label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// THREAT GAUGE — SVG circular gauge for vulnerability score
// ══════════════════════════════════════════════════════════════
function ThreatGauge({vulns}:{vulns:VulnerabilityFinding[]|undefined}){
  const score=useMemo(()=>{
    if(!vulns||vulns.length===0)return 0;
    const raw=vulns.reduce((acc,v)=>{
      const w={critical:25,high:15,medium:8,low:3,info:1}[v.severity]||0;
      return acc+w;
    },0);
    return Math.min(100,raw);
  },[vulns]);

  const R=54;const C=2*Math.PI*R;
  const filled=C*(score/100);
  const color=score>=80?"#ef4444":score>=60?"#f97316":score>=30?"#eab308":"#22c55e";
  const label=score>=80?"خطر عالٍ":score>=60?"متوسط":score>=30?"منخفض":"آمن";
  const ct=vulns?.reduce((a,v)=>{a[v.severity]=(a[v.severity]||0)+1;return a;},{} as Record<string,number>)||{};

  return(
    <div className="bg-card/70 backdrop-blur-sm border border-border rounded-2xl p-4 flex flex-col items-center gap-3 animate-in fade-in duration-300">
      <div className="text-sm font-semibold flex items-center gap-2"><Activity className="w-4 h-4 text-red-400"/>مستوى التهديد</div>
      {/* SVG Gauge */}
      <div className="relative">
        <svg width="140" height="140" viewBox="0 0 140 140">
          {/* Background track */}
          <circle cx="70" cy="70" r={R} fill="none" stroke="currentColor" strokeWidth="10" className="text-muted/30"
            strokeDasharray={C} strokeDashoffset="0" transform="rotate(-90 70 70)"/>
          {/* Score arc */}
          <circle cx="70" cy="70" r={R} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={C} strokeDashoffset={C-filled} transform="rotate(-90 70 70)"
            style={{transition:"stroke-dashoffset 1s ease-out, stroke 0.5s"}}/>
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold" style={{color}}>{score}</span>
          <span className="text-[10px] text-muted-foreground">/100</span>
        </div>
      </div>
      {/* Label badge */}
      <span className="text-xs font-bold px-3 py-1 rounded-full border" style={{color,borderColor:color+"40",backgroundColor:color+"15"}}>{label}</span>
      {/* Breakdown */}
      {vulns&&vulns.length>0&&<div className="w-full grid grid-cols-5 gap-1 text-center">
        {(["critical","high","medium","low","info"] as const).map(s=>{
          const clr={critical:"#ef4444",high:"#f97316",medium:"#eab308",low:"#22c55e",info:"#6b7280"}[s];
          const lbl={critical:"حرج",high:"عالٍ",medium:"متوسط",low:"منخفض",info:"معلومة"}[s];
          return(<div key={s} className="bg-muted/20 rounded-lg py-1.5">
            <div className="text-base font-bold" style={{color:clr}}>{ct[s]||0}</div>
            <div className="text-[9px] text-muted-foreground">{lbl}</div>
          </div>);
        })}
      </div>}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// VULN CHART — horizontal bar chart for severity distribution
// ══════════════════════════════════════════════════════════════
function VulnChart({vulns}:{vulns:VulnerabilityFinding[]|undefined}){
  const rows=useMemo(()=>{
    if(!vulns||vulns.length===0)return[];
    const ct=vulns.reduce((a,v)=>{a[v.severity]=(a[v.severity]||0)+1;return a;},{} as Record<string,number>);
    const max=Math.max(...Object.values(ct),1);
    return([
      {key:"critical",label:"حرج",color:"#ef4444",bg:"bg-red-500"},
      {key:"high",    label:"عالٍ", color:"#f97316",bg:"bg-orange-500"},
      {key:"medium",  label:"متوسط",color:"#eab308",bg:"bg-yellow-500"},
      {key:"low",     label:"منخفض",color:"#22c55e",bg:"bg-green-500"},
      {key:"info",    label:"معلومة",color:"#6b7280",bg:"bg-gray-500"},
    ].filter(r=>ct[r.key]>0).map(r=>({...r,count:ct[r.key]||0,pct:Math.round((ct[r.key]||0)/max*100)})));
  },[vulns]);

  if(!rows.length)return null;
  return(
    <div className="bg-card/70 backdrop-blur-sm border border-border rounded-2xl p-4 space-y-3 animate-in fade-in duration-300">
      <div className="text-sm font-semibold flex items-center gap-2"><BarChart3 className="w-4 h-4 text-violet-400"/>توزيع الثغرات</div>
      <div className="space-y-2">
        {rows.map(r=>(
          <div key={r.key} className="flex items-center gap-2">
            <span className="text-[11px] text-muted-foreground w-12 text-right shrink-0">{r.label}</span>
            <div className="flex-1 h-5 bg-muted/30 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${r.bg} transition-all duration-700 ease-out flex items-center justify-end pr-1.5`}
                style={{width:`${r.pct}%`}}
              >
                {r.pct>20&&<span className="text-[10px] font-bold text-white">{r.count}</span>}
              </div>
            </div>
            {r.pct<=20&&<span className="text-[10px] font-bold shrink-0" style={{color:r.color}}>{r.count}</span>}
          </div>
        ))}
      </div>
      <div className="text-[10px] text-muted-foreground text-center">إجمالي: {vulns?.length} ثغرة</div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// BINARY HEX VIEWER — reads REAL binary data from decompiled files
// ══════════════════════════════════════════════════════════════
function BinaryHexViewer({file,sessionId}:{file:{name:string;size:number;extension:string;path?:string};sessionId?:string}){
  const[rows,setRows]=useState<{offset:string;bytes:string[];ascii:string}[]>([]);
  const[loading,setLoading]=useState(false);
  const[hexOffset,setHexOffset]=useState(0);
  const[totalSize,setTotalSize]=useState(file.size);
  const CHUNK=512;

  useEffect(()=>{
    if(!sessionId||!file.path){return;}
    setLoading(true);
    fetchRE("/api/reverse/hex-dump",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId,filePath:file.path,offset:hexOffset,length:CHUNK})})
      .then(r=>r.json()).then(d=>{
        if(d.rows){setRows(d.rows);setTotalSize(d.totalSize);}
      }).catch(()=>{}).finally(()=>setLoading(false));
  },[sessionId,file.path,hexOffset]);

  const EXT_SIGS:Record<string,string>={exe:"4D5A",dll:"4D5A",msi:"D0CF11E0",apk:"504B03",ipa:"504B03",so:"7F454C46",dex:"6465780A",jar:"504B03",wasm:"0061736D"};
  const sig=EXT_SIGS[file.extension.toLowerCase()]||"";
  const maxOffset=Math.max(0,totalSize-CHUNK);

  return(
    <div className="h-full flex flex-col bg-[#0d1117] font-mono text-[11px] overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/5 bg-white/3 shrink-0">
        <span className="px-2 py-0.5 bg-orange-500/20 border border-orange-500/30 text-orange-300 rounded text-[10px] font-bold">HEX</span>
        <span className="text-muted-foreground/70 truncate">{file.name}</span>
        <span className="mr-auto text-muted-foreground/40">{fmtB(totalSize)}</span>
        {sig&&<span className="text-[9px] text-cyan-400/60 font-mono">{sig}</span>}
        {loading&&<Loader2 className="w-3 h-3 animate-spin text-cyan-400"/>}
      </div>
      <div className="flex items-center gap-2 px-4 py-1 border-b border-white/5 shrink-0">
        <button onClick={()=>setHexOffset(0)} disabled={hexOffset===0} className="px-2 py-0.5 text-[9px] rounded bg-white/5 hover:bg-white/10 disabled:opacity-30 text-cyan-300">البداية</button>
        <button onClick={()=>setHexOffset(Math.max(0,hexOffset-CHUNK))} disabled={hexOffset===0} className="px-2 py-0.5 text-[9px] rounded bg-white/5 hover:bg-white/10 disabled:opacity-30 text-cyan-300">السابق</button>
        <span className="text-[9px] text-muted-foreground/50 flex-1 text-center">0x{hexOffset.toString(16).toUpperCase()} — 0x{Math.min(hexOffset+CHUNK,totalSize).toString(16).toUpperCase()} / 0x{totalSize.toString(16).toUpperCase()}</span>
        <button onClick={()=>setHexOffset(Math.min(maxOffset,hexOffset+CHUNK))} disabled={hexOffset>=maxOffset} className="px-2 py-0.5 text-[9px] rounded bg-white/5 hover:bg-white/10 disabled:opacity-30 text-cyan-300">التالي</button>
        <button onClick={()=>setHexOffset(maxOffset)} disabled={hexOffset>=maxOffset} className="px-2 py-0.5 text-[9px] rounded bg-white/5 hover:bg-white/10 disabled:opacity-30 text-cyan-300">النهاية</button>
      </div>
      <div className="flex items-center gap-4 px-4 py-1 border-b border-white/5 text-[10px] text-muted-foreground/30 shrink-0 select-none">
        <span className="w-20">Offset</span>
        <span className="flex-1">00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
        <span className="w-20 text-right">ASCII</span>
      </div>
      <div className="flex-1 overflow-y-auto px-4 py-2 space-y-0.5">
        {rows.length===0&&!loading&&<div className="text-muted-foreground/40 text-xs py-4 text-center">{sessionId?"اختر ملفاً لعرض البيانات الثنائية":"افتح جلسة تحرير أولاً"}</div>}
        {rows.map((r,i)=>(
          <div key={i} className="flex items-center gap-4 hover:bg-white/3 rounded px-1 -mx-1 transition-colors group">
            <span className="w-20 text-cyan-500/50 shrink-0">{r.offset}</span>
            <span className="flex-1 text-emerald-300/70 tracking-wider">
              {r.bytes.slice(0,8).join(" ")}
              <span className="mx-2 text-white/10">│</span>
              {r.bytes.slice(8).join(" ")}
            </span>
            <span className="w-20 text-right text-orange-300/40 tracking-wider">{r.ascii}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ══════════════════════════════════════════════════════════════
export default function ReverseEngineer(){
  const fRef=useRef<HTMLInputElement>(null);
  const efRef=useRef<HTMLInputElement>(null);
  const cfRef=useRef<HTMLInputElement>(null);
  const editBufRef=useRef<File|null>(null);
  type Tab="analyze"|"clone"|"edit"|"intel"|"forensics"|"cloudpen";
  const[tab,setTab]=useState<Tab>("analyze");

  // Disclaimer
  const[disc,setDisc]=useState(()=>!localStorage.getItem("re_v4"));
  const acceptDisc=()=>{localStorage.setItem("re_v4","1");setDisc(false);};

  // ══ TAB 1: ANALYZE ══
  const[aFile,setAFile]=useState<File|null>(null);
  const[drag,setDrag]=useState(false);
  const[decomp,setDecomp]=useState(false);
  const[res,setRes]=useState<DecompileResult|null>(null);
  const[selNode,setSelNode]=useState<FileTreeNode|null>(null);
  const[selContent,setSelContent]=useState("");
  const[selBinary,setSelBinary]=useState<DecompiledFile|null>(null);
  const[analyzing,setAnalyzing]=useState(false);
  const[aiText,setAiText]=useState("");
  const[showAi,setShowAi]=useState(false);
  const[dlId,setDlId]=useState("");
  const[aSessId,setASessId]=useState("");
  const[liveStream,setLiveStream]=useState<{sseUrl:string}|null>(null);

  // ══ TAB 2: CLONE ══
  const[cFile,setCFile]=useState<File|null>(null);
  const[cloning,setCloning]=useState(false);
  const[cloneLive,setCloneLive]=useState<{sseUrl:string}|null>(null);
  const[cOpts,setCOpts]=useState({removeAds:true,unlockPremium:true,removeTracking:false,removeLicenseCheck:true,changeAppName:"",changePackageName:"",customInstructions:""});
  const[cResult,setCResult]=useState<CloneResult | null>(null);

  // ══ TAB 3: EDIT ══
  const[eFile,setEFile]=useState<File|null>(null);
  const[eDecomp,setEDecomp]=useState(false);
  const[eSess,setESess]=useState<EditSession|null>(null);
  const[eNode,setENode]=useState<FileTreeNode|null>(null);
  const[eContent,setEContent]=useState("");
  const[eOrig,setEOrig]=useState("");
  const[eMods,setEMods]=useState<Set<string>>(new Set());
  const[saving,setSaving]=useState(false);
  const[eCache,setECache]=useState<Map<string,string>>(new Map());
  const[eType,setEType]=useState("apk");
  // Smart modify
  const[smartInst,setSmartInst]=useState("");
  const[smarting,setSmarting]=useState(false);
  const[smartRes,setSmartRes]=useState<SmartModifyResult|null>(null);
  // Search
  const[sq,setSq]=useState("");
  const[searching,setSearching]=useState(false);
  const[sResults,setSResults]=useState<any[]>([]);
  // Per-file modify
  const[aiInst,setAiInst]=useState("");
  const[modifying,setModifying]=useState(false);
  const[pending,setPending]=useState<{modifiedCode:string;explanation:string}|null>(null);
  // Build
  const[building,setBuilding]=useState(false);
  const[sessMins,setSessMins]=useState(30);
  // Undo/Redo
  const[editHistory,setEditHistory]=useState<{content:string;path:string;desc:string}[]>([]);
  const[histIdx,setHistIdx]=useState(-1);
  const pushHistory=(content:string,filePath:string,desc:string)=>{const h=editHistory.slice(0,histIdx+1);h.push({content,path:filePath,desc});setEditHistory(h);setHistIdx(h.length-1);};
  const undoEdit=()=>{if(histIdx>0){const prev=editHistory[histIdx-1];setEContent(prev.content);setHistIdx(histIdx-1);toast.info(`تراجع: ${editHistory[histIdx].desc}`);}};
  const redoEdit=()=>{if(histIdx<editHistory.length-1){const next=editHistory[histIdx+1];setEContent(next.content);setHistIdx(histIdx+1);toast.info(`إعادة: ${next.desc}`);}};

  // ══ TAB 4: INTEL ══
  const[intel,setIntel]=useState<IntelReport|null>(null);
  const[intelLoading,setIntelLoading]=useState(false);
  const[irPat,setIrPat]=useState("");
  const[irRes,setIrRes]=useState<any[]>([]);
  const[irSearching,setIrSearching]=useState(false);
  const[irCat,setIrCat]=useState("");
  const[showKeys,setShowKeys]=useState(false);
  const[treeFilter,setTreeFilter]=useState("");
  const[editTreeFilter,setEditTreeFilter]=useState("");
  const[intelTreeFilter,setIntelTreeFilter]=useState("");
  const[forensicsTreeFilter,setForensicsTreeFilter]=useState("");
  const[intelSelNode,setIntelSelNode]=useState<FileTreeNode|null>(null);
  const[intelSelContent,setIntelSelContent]=useState("");
  const[forensicsSelNode,setForensicsSelNode]=useState<FileTreeNode|null>(null);
  const[forensicsSelContent,setForensicsSelContent]=useState("");

  // ══ TAB 5: FORENSICS ══
  const[fDecoded,setFDecoded]=useState<any[]>([]);
  const[fDecodedLoading,setFDecodedLoading]=useState(false);
  const[fXref,setFXref]=useState<any>(null);
  const[fXrefLoading,setFXrefLoading]=useState(false);
  const[fXrefQuery,setFXrefQuery]=useState("");
  const[fHierarchy,setFHierarchy]=useState<any>(null);
  const[fHierarchyLoading,setFHierarchyLoading]=useState(false);
  const[fDataFlow,setFDataFlow]=useState<any>(null);
  const[fDataFlowLoading,setFDataFlowLoading]=useState(false);
  const[fMethodSearch,setFMethodSearch]=useState<any>(null);
  const[fMethodLoading,setFMethodLoading]=useState(false);
  const[fMethodQuery,setFMethodQuery]=useState("");
  const[fDiff,setFDiff]=useState<any>(null);
  const[fDiffLoading,setFDiffLoading]=useState(false);
  const fDiffRef1=useRef<HTMLInputElement>(null);
  const fDiffRef2=useRef<HTMLInputElement>(null);
  const[fDiffFile1,setFDiffFile1]=useState<File|null>(null);
  const[fDiffFile2,setFDiffFile2]=useState<File|null>(null);
  const[fReportLoading,setFReportLoading]=useState(false);
  const[fPanel,setFPanel]=useState<"decode"|"xref"|"hierarchy"|"dataflow"|"methods"|"diff"|"report">("decode");
  const[decompStep,setDecompStep]=useState(0);
  const[statsAnim,setStatsAnim]=useState(false);

  // ══ TAB 6: CLOUD PENTEST ══
  const[cpResult,setCpResult]=useState<any>(null);
  const[cpLoading,setCpLoading]=useState(false);
  const[cpExpanded,setCpExpanded]=useState<Set<number>>(new Set([1]));
  const[cpShowReport,setCpShowReport]=useState(false);
  const[cpFile,setCpFile]=useState<File|null>(null);
  const[cpActiveStep,setCpActiveStep]=useState(0);
  const[cpStepsRevealed,setCpStepsRevealed]=useState<number[]>([]);
  const cpFileRef=useRef<HTMLInputElement>(null);

  // Auto-run Intel when switching to intel tab with active session
  useEffect(()=>{
    if(tab==="intel"&&iSess&&!intel&&!intelLoading){
      doIntel();
    }
  },[tab]);

  // Auto-run Decode when switching to forensics tab with active session
  useEffect(()=>{
    if(tab==="forensics"&&iSess&&fDecoded.length===0&&!fDecodedLoading){
      doDecodeStrings();
    }
  },[tab]);

  // StatsAnim — triggers card entrance animation when result arrives
  useEffect(()=>{
    if(!res){setStatsAnim(false);return;}
    const t=setTimeout(()=>setStatsAnim(true),80);
    return()=>clearTimeout(t);
  },[res]);

  // DecompStep animation — increments every 1800ms while decomp is running
  useEffect(()=>{
    if(!decomp){setDecompStep(0);return;}
    setDecompStep(0);
    const iv=setInterval(()=>{
      setDecompStep(s=>s<4?s+1:4);
    },1800);
    return()=>clearInterval(iv);
  },[decomp]);

  // Session timer
  useEffect(()=>{
    if(!eSess)return;
    const iv=setInterval(async()=>{try{const r=await fetch(`/api/reverse/session/${eSess.sessionId}`,{credentials:"include"});const d=await r.json();if(d.exists){setSessMins(d.minutesLeft);setEMods(new Set(d.modifiedPaths));}else{setESess(null);toast.error("انتهت الجلسة");}}catch{}},60000);
    return()=>clearInterval(iv);
  },[eSess]);

  // Ctrl+S
  useEffect(()=>{
    const h=(e:KeyboardEvent)=>{if((e.ctrlKey||e.metaKey)&&e.key==="s"&&tab==="edit"){e.preventDefault();doSave();}};
    window.addEventListener("keydown",h);return()=>window.removeEventListener("keydown",h);
  },[tab,eContent,eSess,eNode]);

  const valid=(f:File)=>{const e=f.name.split(".").pop()?.toLowerCase();if(!e||!ALL_FORMATS.includes(e as any)){toast.error(`صيغة غير مدعومة: .${e}`);return false;}return true;};

  const decompResultRef=useRef<any>(null);
  const decompResolveRef=useRef<(()=>void)|null>(null);
  const handleDecompResult=useCallback((d:any)=>{
    setRes(d);if(d.downloadId)setDlId(d.downloadId);
    if(d.totalFiles>0)toast.success(`✅ ${d.totalFiles} ملف`);
    decompResultRef.current=d;
  },[]);
  const handleDecompComplete=useCallback(()=>{
    if(decompResolveRef.current)decompResolveRef.current();
  },[]);

  // ═══ TAB 1 HANDLERS ═══
  const doDecompile=async()=>{
    if(!aFile)return;setDecomp(true);setRes(null);setAiText("");setSelNode(null);setSelContent("");setLiveStream(null);
    decompResultRef.current=null;
    const fd=new FormData();fd.append("file",aFile);
    try{
      const upR=await fetchRE("/api/reverse/upload",{method:"POST",body:fd});
      const upD=await upR.json();
      if(!upR.ok){toast.error(upD.error||"فشل رفع الملف");setDecomp(false);return;}
      const sseUrl=`/api/reverse/stream/decompile?uploadId=${upD.uploadId}`;
      setLiveStream({sseUrl});
      await new Promise<void>((resolve)=>{decompResolveRef.current=resolve;setTimeout(resolve,300000);});
      const fd2=new FormData();fd2.append("file",aFile);
      try{const r2=await fetchRE("/api/reverse/decompile-for-edit",{method:"POST",body:fd2});const d2=await r2.json();if(r2.ok&&d2.sessionId){setASessId(d2.sessionId);setESess(d2);setEType(d2.fileType||"apk");setEMods(new Set());setSessMins(30);toast.success("✅ الجلسة جاهزة");}else{toast.error(d2.error||"فشل إنشاء جلسة التحرير");}}catch(e:any){toast.error(e.message||"فشل إنشاء جلسة التحرير");}
    }catch(e:any){toast.error(e.message);}finally{setDecomp(false);}
  };
  const doSelNode=(n:FileTreeNode)=>{setSelNode(n);setAiText("");setShowAi(false);if(res){const f=res.files.find(f=>f.path===n.path);if(f?.isBinary){setSelBinary(f);setSelContent("");}else{setSelBinary(null);setSelContent(f?.content||"لا محتوى");}}};
  const doAiAnalysis=async(type:string)=>{
    if(!selContent||selContent.startsWith("["))return;setAnalyzing(true);setShowAi(true);setAiText("");
    try{const r=await fetchRE("/api/reverse/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:selContent,fileName:selNode?.name,analysisType:type})});const d=await r.json();if(!r.ok){toast.error(d.error);setShowAi(false);return;}setAiText(d.analysis);}catch(e:any){toast.error(e.message);setShowAi(false);}finally{setAnalyzing(false);}
  };

  const cloneResultRef=useRef<any>(null);
  const cloneResolveRef=useRef<(()=>void)|null>(null);
  const handleCloneResult=useCallback((d:any)=>{cloneResultRef.current=d;},[]);
  const handleCloneComplete=useCallback(()=>{if(cloneResolveRef.current)cloneResolveRef.current();},[]);

  // ═══ TAB 2 HANDLERS ═══
  const doClone=async()=>{
    if(!cFile)return;setCloning(true);setCResult(null);setCloneLive(null);
    cloneResultRef.current=null;
    const fd=new FormData();fd.append("file",cFile);
    try{
      const upR=await fetchRE("/api/reverse/upload",{method:"POST",body:fd});
      const upD=await upR.json();
      if(!upR.ok){toast.error(upD.error||"فشل رفع الملف");setCloning(false);return;}
      const opts=encodeURIComponent(JSON.stringify(cOpts));
      const sseUrl=`/api/reverse/stream/clone?uploadId=${upD.uploadId}&opts=${opts}`;
      setCloneLive({sseUrl});
      await new Promise<void>((resolve)=>{cloneResolveRef.current=resolve;setTimeout(resolve,300000);});
      const cloneResult=cloneResultRef.current;
      if(cloneResult?.success&&cloneResult.downloadId){
        const dlR=await fetchRE(`/api/reverse/stream/download/${cloneResult.downloadId}`);
        if(dlR.ok){
          const blob=await dlR.blob();const dlUrl=URL.createObjectURL(blob);const a=document.createElement("a");a.href=dlUrl;
          const ext=cFile.name.split(".").pop()?.toLowerCase();
          const bn=cFile.name.replace(/\.[^.]+$/,"");a.download=ext==="apk"?`cloned-${bn}.apk`:`cloned-${bn}.zip`;a.click();
          setCResult({modifications:cloneResult.modifications||[],patchedFiles:cloneResult.patchedFiles||0,signed:cloneResult.signed||false,downloadUrl:dlUrl,installCommand:ext==="apk"?"adb install -r cloned-"+cFile.name:undefined,success:true});
          toast.success(cloneResult.signed?"🎉 استنساخ + توقيع — جاهز!":"✅ تم الاستنساخ");
        }else{setCResult({modifications:cloneResult.modifications||[],success:false});toast.error("فشل تحميل الملف المستنسخ");}
      }else{
        setCResult({modifications:cloneResult?.modifications||[],success:false});
        toast.error(cloneResult?.error||"فشل الاستنساخ");
      }
    }catch(e:any){toast.error(e.message);}finally{setCloning(false);}
  };

  // ═══ TAB 3 HANDLERS ═══
  const doEditDecomp=async()=>{
    if(!eFile)return;setEDecomp(true);setESess(null);setECache(new Map());setENode(null);setEContent("");
    editBufRef.current=eFile;const fd=new FormData();fd.append("file",eFile);
    try{const r=await fetchRE("/api/reverse/decompile-for-edit",{method:"POST",body:fd});const d=await r.json();if(!r.ok){toast.error(d.error);return;}setESess(d);setEType(d.fileType||"apk");setEMods(new Set());setSessMins(30);toast.success(`✅ ${d.fileCount} ملف [${(d.fileType||"apk").toUpperCase()}]`);}catch(e:any){toast.error(e.message);}finally{setEDecomp(false);}
  };

  const loadFile=useCallback(async(node:FileTreeNode)=>{
    if(node.type==="folder")return;setENode(node);setPending(null);
    if(eCache.has(node.path)){const c=eCache.get(node.path)!;setEContent(c);setEOrig(c);pushHistory(c,node.path,"فتح "+node.name);return;}
    if(!eSess)return;
    try{const r=await fetch("/api/reverse/file-content",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:eSess.sessionId,filePath:node.path})});const d=await r.json();if(!r.ok){setEContent(`[خطأ: ${d.error}]`);return;}const c=d.content??"";setECache(p=>new Map(p).set(node.path,c));setEContent(c);setEOrig(c);pushHistory(c,node.path,"فتح "+node.name);}catch{setEContent("[تعذر القراءة]");}
  },[eCache,eSess]);

  const doSave=async()=>{
    if(!eSess||!eNode)return;setSaving(true);
    try{const r=await fetch("/api/reverse/save-edit",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:eSess.sessionId,filePath:eNode.path,content:eContent})});const d=await r.json();if(!r.ok){toast.error(d.error);return;}setEMods(p=>new Set(p).add(eNode.path));setEOrig(eContent);setECache(p=>new Map(p).set(eNode.path,eContent));toast.success("✅ حفظ");}catch(e:any){toast.error(e.message);}finally{setSaving(false);}
  };

  const doSmartModify=async()=>{
    if(!eSess||!smartInst.trim())return;setSmarting(true);setSmartRes(null);
    try{const r=await fetchRE("/api/reverse/ai-smart-modify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:eSess.sessionId,instruction:smartInst})});const d=await r.json();if(!r.ok){toast.error(d.error);return;}setSmartRes(d);if(d.filesModified>0){const i=await(await fetch(`/api/reverse/session/${eSess.sessionId}`,{credentials:"include"})).json();if(i.exists)setEMods(new Set(i.modifiedPaths));}toast.success(`✅ ${d.filesModified} ملف`);}catch(e:any){toast.error(e.message);}finally{setSmarting(false);}
  };

  const doSearch=async()=>{
    if(!sq.trim()||!eSess)return;setSearching(true);setSResults([]);
    try{const r=await fetch("/api/reverse/ai-search",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:eSess.sessionId,query:sq})});const d=await r.json();if(!r.ok){toast.error(d.error);return;}setSResults(d.results);}catch(e:any){toast.error(e.message);}finally{setSearching(false);}
  };

  const doAiModify=async()=>{
    if(!eContent||!aiInst||!eNode)return;setModifying(true);setPending(null);
    try{const r=await fetch("/api/reverse/ai-modify",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:eContent,instruction:aiInst,fileName:eNode.name})});const d=await r.json();if(!r.ok){toast.error(d.error);return;}setPending(d);}catch(e:any){toast.error(e.message);}finally{setModifying(false);}
  };
  const applyMod=()=>{if(!pending||!eNode)return;pushHistory(eContent,eNode.path,"قبل تعديل AI");setEContent(pending.modifiedCode);setPending(null);toast.success("تطبيق — اضغط حفظ");};

  const doBuild=async()=>{
    if(!eSess||eMods.size===0){toast.error("لا تعديلات!");return;}setBuilding(true);
    try{const r=await fetchRE("/api/reverse/rebuild",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:eSess.sessionId})});if(!r.ok){const d=await r.json();throw new Error(d.error);}const blob=await r.blob();const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=r.headers.get("X-APK-Signed")==="true"?"modified-signed.apk":`modified.${eType==="apk"?"apk":"zip"}`;a.click();URL.revokeObjectURL(url);toast.success(r.headers.get("X-APK-Signed")==="true"?"🎉 APK موقّع!":"✅ بناء");}catch(e:any){toast.error(e.message);}finally{setBuilding(false);}
  };

  const sharedTree:FileTreeNode[]=eSess?.structure||res?.structure||[];

  const sharedNodeRef=useRef<{intel:string;forensics:string}>({intel:"",forensics:""});

  const doSharedNodeSelect=async(node:FileTreeNode,target:"intel"|"forensics")=>{
    if(node.type==="folder")return;
    const setter=target==="intel"?setIntelSelContent:setForensicsSelContent;
    const nodeSetter=target==="intel"?setIntelSelNode:setForensicsSelNode;
    nodeSetter(node);
    sharedNodeRef.current[target]=node.path;
    if(eCache.has(node.path)){setter(eCache.get(node.path)!);return;}
    const sid=eSess?.sessionId||aSessId;
    if(!sid){
      const f=res?.files?.find(f2=>f2.path===node.path);
      if(f?.content){setter(f.content);return;}
      setter("// لا يوجد محتوى متاح");return;
    }
    try{
      const r=await fetch(`/api/reverse/file-content?sessionId=${sid}&filePath=${encodeURIComponent(node.path)}`,{credentials:"include"});
      if(sharedNodeRef.current[target]!==node.path)return;
      if(!r.ok){setter("// خطأ في تحميل الملف");return;}
      const d=await r.json();
      const content=d.content||"";
      eCache.set(node.path,content);
      setter(content);
    }catch{setter("// خطأ في الاتصال");}
  };

  // ═══ TAB 4 HANDLERS ═══
  const iSess=eSess?.sessionId||aSessId;
  const doIntel=async()=>{
    if(!iSess){toast.error("افتح ملفاً أولاً");return;}setIntelLoading(true);setIntel(null);
    try{const r=await fetchRE("/api/reverse/intelligence-report",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:iSess})});const d=await r.json();if(!r.ok){toast.error(d.error);return;}setIntel(d);}catch(e:any){toast.error(e.message);}finally{setIntelLoading(false);}
  };
  const doRegex=async(pat?:string,cat?:string)=>{
    if(!iSess)return;setIrSearching(true);setIrRes([]);
    try{const r=await fetch("/api/reverse/regex-search",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:iSess,pattern:pat||irPat,category:cat})});const d=await r.json();if(!r.ok){toast.error(d.error);return;}setIrRes(d.results);}catch(e:any){toast.error(e.message);}finally{setIrSearching(false);}
  };

  // ═══ TAB 5 HANDLERS ═══
  const doDecodeStrings=async()=>{
    if(!iSess){toast.error("افتح ملفاً أولاً");return;}setFDecodedLoading(true);setFDecoded([]);
    try{const r=await fetchRE("/api/reverse/decode-strings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:iSess})});const d=await r.json();if(!r.ok)throw new Error(d.error);setFDecoded(d.decoded||[]);toast.success(`تم فك ${d.total||0} نص مشفر`);}catch(e:any){toast.error(e.message);}finally{setFDecodedLoading(false);}
  };
  const doXref=async()=>{
    if(!iSess||!fXrefQuery.trim()){toast.error("أدخل اسم كلاس أو ميثود");return;}setFXrefLoading(true);setFXref(null);
    try{const r=await fetchRE("/api/reverse/cross-reference",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:iSess,target:fXrefQuery})});const d=await r.json();if(!r.ok)throw new Error(d.error);setFXref(d);toast.success(`${d.totalCount} مرجع`);}catch(e:any){toast.error(e.message);}finally{setFXrefLoading(false);}
  };
  const doHierarchy=async()=>{
    if(!iSess){toast.error("افتح ملفاً أولاً");return;}setFHierarchyLoading(true);setFHierarchy(null);
    try{const r=await fetchRE("/api/reverse/class-hierarchy",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:iSess})});const d=await r.json();if(!r.ok)throw new Error(d.error);setFHierarchy(d);toast.success(`${d.stats?.totalClasses} كلاس`);}catch(e:any){toast.error(e.message);}finally{setFHierarchyLoading(false);}
  };
  const doDataFlow=async()=>{
    if(!iSess){toast.error("افتح ملفاً أولاً");return;}setFDataFlowLoading(true);setFDataFlow(null);
    try{const r=await fetchRE("/api/reverse/data-flow",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:iSess})});const d=await r.json();if(!r.ok)throw new Error(d.error);setFDataFlow(d);toast.success("تحليل تدفق البيانات مكتمل");}catch(e:any){toast.error(e.message);}finally{setFDataFlowLoading(false);}
  };
  const doMethodSearch=async()=>{
    if(!iSess||!fMethodQuery.trim()){toast.error("أدخل اسم ميثود");return;}setFMethodLoading(true);setFMethodSearch(null);
    try{const r=await fetchRE("/api/reverse/method-search",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:iSess,query:fMethodQuery})});const d=await r.json();if(!r.ok)throw new Error(d.error);setFMethodSearch(d);toast.success(`${d.totalFound} ميثود`);}catch(e:any){toast.error(e.message);}finally{setFMethodLoading(false);}
  };
  const doDiff=async()=>{
    if(!fDiffFile1||!fDiffFile2){toast.error("ارفع ملفين للمقارنة");return;}setFDiffLoading(true);setFDiff(null);
    try{const fd=new FormData();fd.append("file1",fDiffFile1);fd.append("file2",fDiffFile2);const r=await fetchRE("/api/reverse/diff",{method:"POST",body:fd});const d=await r.json();if(!r.ok)throw new Error(d.error);setFDiff(d);toast.success("المقارنة مكتملة");}catch(e:any){toast.error(e.message);}finally{setFDiffLoading(false);}
  };
  const doForensicReport=async()=>{
    if(!iSess){toast.error("افتح ملفاً أولاً");return;}setFReportLoading(true);
    try{const r=await fetchRE("/api/reverse/forensic-report",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sessionId:iSess,analyses:{decodedStrings:true,classHierarchy:true,dataFlow:true,networkEndpoints:true,obfuscation:true,malware:true}})});const d=await r.json();if(!r.ok)throw new Error(d.error);const blob=new Blob([JSON.stringify(d.report,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`forensic-report-${iSess}.json`;a.click();URL.revokeObjectURL(url);toast.success("تم تصدير التقرير");}catch(e:any){toast.error(e.message);}finally{setFReportLoading(false);}
  };

  // ═══ TAB 6 HANDLERS ═══
  const doCloudPentestFull=async()=>{
    if(!cpFile){toast.error("ارفع ملف APK أولاً");return;}
    setCpLoading(true);setCpResult(null);setCpShowReport(false);setCpActiveStep(1);setCpStepsRevealed([]);
    const revealStep=(n:number)=>setCpStepsRevealed(prev=>[...prev,n]);
    const stepTitles=["تفكيك APK","استخراج التوكن","المفاتيح","IDOR","استغلال","سحب DB","Telegram","سكريبت + تقرير"];
    let stepTimer:any;
    const simulateSteps=()=>{
      let s=1;
      revealStep(1);setCpActiveStep(1);
      stepTimer=setInterval(()=>{s++;if(s<=8){revealStep(s);setCpActiveStep(s);}else clearInterval(stepTimer);},2400);
    };
    simulateSteps();
    try{
      const fd=new FormData();fd.append("file",cpFile);
      const r=await fetchRE("/api/reverse/cloud-pentest-full",{method:"POST",body:fd});
      const d=await r.json();
      if(!r.ok)throw new Error(d.error);
      clearInterval(stepTimer);
      setCpStepsRevealed([1,2,3,4,5,6,7,8]);setCpActiveStep(0);
      setCpResult(d);setCpExpanded(new Set([1,2,3,4,5,6,7,8]));
      toast.success(`اكتمل اختبار الاختراق — درجة الخطورة: ${d.summary?.riskScore}/100`);
    }catch(e:any){clearInterval(stepTimer);toast.error(e.message);}finally{setCpLoading(false);}
  };

  // ═══ RENDER ═══
  const[showTools,setShowTools]=useState(false);
  const[tools,setTools]=useState<any>(null);
  const loadTools=async()=>{setShowTools(t=>!t);if(tools)return;try{const r=await fetch("/api/reverse/check-tools",{credentials:"include"});const d=await r.json();setTools(d);}catch{}};

  const tabs:{id:Tab;label:string;icon:LucideIcon}[]=[{id:"analyze",label:"تحليل",icon:Eye},{id:"clone",label:"استنساخ",icon:GitBranch},{id:"edit",label:"تحرير & بناء",icon:Hammer},{id:"intel",label:"استخبارات",icon:Fingerprint},{id:"forensics",label:"طب شرعي",icon:Microscope},{id:"cloudpen",label:"اختراق سحابي",icon:Database}];

  return(<DashboardLayout>
    {/* Disclaimer */}
    <Dialog open={disc} onOpenChange={()=>{}}><DialogContent className="max-w-md" dir="rtl"><DialogHeader><DialogTitle className="flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-amber-400"/>تنبيه قانوني</DialogTitle><DialogDescription asChild><div className="text-right text-sm space-y-2"><span className="block">للاستخدام المشروع فقط:</span><span className="block text-emerald-400 text-xs">✅ تفكيك تطبيقاتك · استعادة كود · تحليل أمني</span><span className="block text-red-400 text-xs">❌ تطبيقات الآخرين بدون إذن</span></div></DialogDescription></DialogHeader><DialogFooter><Button onClick={acceptDisc} className="w-full">أوافق</Button></DialogFooter></DialogContent></Dialog>

    <div className="flex flex-col h-full p-4 gap-4" dir="rtl">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="relative shrink-0"><div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500/30 to-cyan-500/30 flex items-center justify-center border border-emerald-500/40 shadow-[0_0_12px_rgba(16,185,129,0.25)]"><ScanSearch className="w-5 h-5 text-emerald-400"/></div><span className="absolute -top-1.5 -left-1.5 text-[8px] font-black bg-gradient-to-r from-emerald-400 to-cyan-400 text-black px-1.5 py-0.5 rounded-full shadow-[0_0_6px_rgba(16,185,129,0.6)]">v4</span></div>
        <div className="flex-1 min-w-0">
          <h1 className="text-lg font-black tracking-widest bg-gradient-to-l from-emerald-400 via-cyan-300 to-blue-400 bg-clip-text text-transparent leading-tight">RE:PLATFORM</h1>
          <div className="flex flex-wrap gap-1 mt-0.5">
            {ALL_FORMATS.map(f=>(
              <span key={f} className="text-[9px] font-bold font-mono px-1.5 py-0.5 rounded border border-emerald-500/20 bg-emerald-500/5 text-emerald-400/70 hover:bg-emerald-500/20 hover:text-emerald-300 hover:border-emerald-500/40 hover:scale-105 transition-all cursor-default select-none">{f.toUpperCase()}</span>
            ))}
          </div>
        </div>
        <button onClick={loadTools} title="أدوات مثبّتة" className={`mr-auto p-2 rounded-lg border transition-all ${showTools?"bg-emerald-500/20 border-emerald-500/40 text-emerald-400":"border-border text-muted-foreground hover:text-foreground hover:bg-muted/30"}`}>
          <Wrench className="w-4 h-4"/>
        </button>
        <button onClick={()=>setShowKeys(k=>!k)} title="اختصارات لوحة المفاتيح" className={`p-2 rounded-lg border transition-all ${showKeys?"bg-primary/20 border-primary/40 text-primary":"border-border text-muted-foreground hover:text-foreground hover:bg-muted/30"}`}>
          <Keyboard className="w-4 h-4"/>
        </button>
      </div>

      {showTools&&<div className="bg-card/70 backdrop-blur-sm border border-emerald-500/30 rounded-2xl p-4 animate-in fade-in slide-in-from-top-2 duration-200">
        <div className="flex items-center gap-2 mb-3"><Wrench className="w-4 h-4 text-emerald-400"/><span className="text-sm font-semibold">أدوات الهندسة العكسية المثبّتة</span><button onClick={()=>setShowTools(false)} className="mr-auto text-muted-foreground hover:text-foreground"><X className="w-4 h-4"/></button></div>
        {!tools?<div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="w-4 h-4 animate-spin"/>جاري الفحص...</div>:
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {([
            ["Java JDK 17","javaAvailable","☕"],
            ["JADX","jadxVersion","🔍"],
            ["APKTool","apkToolAvailable","📦"],
            ["jarsigner","jarsignerAvailable","✍️"],
            ["keytool","keytoolAvailable","🔑"],
            ["Keystore","keystoreExists","🔐"],
            ["wasm2wat","wasm2watAvailable","🌐"],
            ["readelf","readelfAvailable","📊"],
            ["objdump","objdumpAvailable","⚙️"],
            ["strings","stringsAvailable","🔤"],
            ["xxd","xxdAvailable","🔢"],
            ["APKTool v","apkToolVersion","📋"],
          ] as const).map(([name,key,icon])=>{
            const val=tools[key];
            const ok=val&&val!==null&&val!==false;
            return(<div key={name} className={`flex items-center gap-2 px-2.5 py-2 rounded-lg border text-xs ${ok?"bg-emerald-500/5 border-emerald-500/20 text-emerald-300":"bg-red-500/5 border-red-500/20 text-red-400"}`}>
              <span>{icon}</span><span className="font-medium">{name}</span><span className="mr-auto text-[10px]">{ok?(typeof val==="string"?val:"✅"):"❌"}</span>
            </div>);
          })}
        </div>}
      </div>}

      {/* Keyboard shortcuts panel */}
      {showKeys&&<div className="bg-card/70 backdrop-blur-sm border border-primary/30 rounded-2xl p-4 animate-in fade-in slide-in-from-top-2 duration-200">
        <div className="flex items-center gap-2 mb-3"><Keyboard className="w-4 h-4 text-primary"/><span className="text-sm font-semibold">اختصارات لوحة المفاتيح</span><button onClick={()=>setShowKeys(false)} className="mr-auto text-muted-foreground hover:text-foreground"><X className="w-4 h-4"/></button></div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {([
            ["Ctrl + S","حفظ الملف الحالي","text-emerald-400"],
            ["Ctrl + B","بناء APK / تعديل","text-blue-400"],
            ["Ctrl + F","البحث في الشجرة","text-violet-400"],
          ] as const).map(([keys,desc,cls])=>(
            <div key={keys} className="flex items-center gap-3 bg-muted/20 rounded-xl px-3 py-2.5 border border-border">
              <kbd className={`font-mono text-[11px] font-bold px-2 py-0.5 rounded-md border ${cls} border-current bg-current/10 shrink-0`}>{keys}</kbd>
              <span className="text-xs text-muted-foreground">{desc}</span>
            </div>
          ))}
        </div>
      </div>}

      {/* Tabs */}
      <div className="flex gap-1 bg-muted/30 rounded-xl p-1 self-start border border-border flex-wrap">
        {tabs.map(t=>{
          const hasSession=(t.id==="intel"||t.id==="forensics")&&!!iSess;
          return(<button key={t.id} onClick={()=>setTab(t.id)} className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all relative ${tab===t.id?"bg-card shadow text-foreground border border-border":"text-muted-foreground hover:text-foreground"}`}><t.icon className="w-4 h-4"/>{t.label}{hasSession&&<span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"/>}</button>);
        })}
        {eSess&&<span className="self-center text-[10px] text-muted-foreground mr-2">⏱{sessMins}م</span>}
      </div>

      {/* ═══ TAB 1: ANALYZE ═══ */}
      {tab==="analyze"&&(
        <AnalysisTab
          fRef={fRef}
          acceptStr={ACCEPT_STR}
          allFormats={ALL_FORMATS}
          formatIconMap={FMT_ICON}
          aFile={aFile}
          drag={drag}
          decomp={decomp}
          decompStep={decompStep}
          res={res}
          selNode={selNode}
          selContent={selContent}
          selBinary={selBinary}
          analyzing={analyzing}
          showAi={showAi}
          aiText={aiText}
          dlId={dlId}
          aSessId={aSessId}
          eSessId={eSess?.sessionId}
          liveStream={liveStream}
          statsAnim={statsAnim}
          treeFilter={treeFilter}
          valid={valid}
          fmtB={fmtB}
          dangerPerms={DANGER_PERMS}
          setDrag={setDrag}
          setAFile={setAFile}
          setRes={setRes}
          setShowAi={setShowAi}
          setTreeFilter={setTreeFilter}
          doDecompile={doDecompile}
          doSelNode={doSelNode}
          doAiAnalysis={doAiAnalysis}
          doIntel={doIntel}
          doDecodeStrings={doDecodeStrings}
          setTab={setTab}
          handleDecompResult={handleDecompResult}
          handleDecompComplete={handleDecompComplete}
          LiveTerminal={LiveTerminal}
          ProgressSteps={ProgressSteps}
          VPanel={VPanel}
          TNode={TNode}
          BinaryHexViewer={BinaryHexViewer}
          lang={lang}
          registerSmaliLanguage={registerSmaliLanguage}
        />
      )}

      {/* ═══ TAB 2: CLONE ═══ */}
      {tab==="clone"&&(
        <CloneTab
          cfRef={cfRef}
          acceptStr={ACCEPT_STR}
          allFormats={ALL_FORMATS}
          cFile={cFile}
          cOpts={cOpts}
          cloning={cloning}
          cloneLive={cloneLive}
          cResult={cResult}
          valid={valid}
          fmtB={fmtB}
          formatIconMap={FMT_ICON}
          doClone={doClone}
          setCFile={setCFile}
          setCResult={setCResult}
          setCOpts={setCOpts}
          handleCloneResult={handleCloneResult}
          handleCloneComplete={handleCloneComplete}
          LiveTerminal={LiveTerminal}
        />
      )}

      {/* ═══ TAB 3: EDIT & BUILD ═══ */}
      {tab==="edit"&&<div className="flex-1 flex flex-col gap-4 min-h-0">
        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="outline" size="sm" className="gap-2 h-9" onClick={()=>efRef.current?.click()}><Upload className="w-4 h-4"/>{eFile?eFile.name.slice(0,20)+"…":"رفع ملف"}</Button>
          <input ref={efRef} type="file" accept={ACCEPT_STR} className="hidden" onChange={e=>{const f=e.target.files?.[0];if(f&&valid(f)){setEFile(f);editBufRef.current=f;setESess(null);setECache(new Map());setENode(null);setEContent("");}}}/>
          {eFile&&!eSess&&<Button onClick={doEditDecomp} disabled={eDecomp} size="sm" className="gap-2 bg-emerald-600 h-9">{eDecomp?<><Loader2 className="w-4 h-4 animate-spin"/>تفكيك...</>:<><Binary className="w-4 h-4"/>فتح</>}</Button>}
          {eSess&&eNode&&<><Button onClick={undoEdit} disabled={histIdx<=0} size="sm" variant="ghost" className="h-9 w-9 p-0" title="تراجع"><Undo2 className="w-4 h-4"/></Button><Button onClick={redoEdit} disabled={histIdx>=editHistory.length-1} size="sm" variant="ghost" className="h-9 w-9 p-0" title="إعادة"><ArrowUpDown className="w-4 h-4"/></Button><Button onClick={doSave} disabled={saving} size="sm" variant="outline" className="gap-2 h-9 border-emerald-500/30">{saving?<Loader2 className="w-4 h-4 animate-spin"/>:<Save className="w-4 h-4 text-emerald-400"/>}حفظ</Button></>}
          {eSess&&<Button onClick={doBuild} disabled={building||eMods.size===0} size="sm" className="gap-2 bg-primary h-9 mr-auto">{building?<><Loader2 className="w-4 h-4 animate-spin"/>بناء...</>:<><Hammer className="w-4 h-4"/>بناء ({eMods.size})</>}</Button>}
        </div>
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-[260px_1fr_280px] gap-4 min-h-0" style={{minHeight:"500px"}}>
          {/* Tree + Search */}
          <div className="flex flex-col gap-3 min-h-0">
            <div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-3 space-y-2">
              <div className="text-xs font-semibold flex items-center gap-1.5"><Search className="w-3.5 h-3.5 text-primary"/>بحث ذكي</div>
              <div className="flex gap-1"><input value={sq} onChange={e=>setSq(e.target.value)} onKeyDown={e=>e.key==="Enter"&&doSearch()} placeholder="ابحث عن: الدفع، الإعلانات..." className="flex-1 bg-muted/30 border border-border rounded-lg px-2 py-1.5 text-xs text-right placeholder:text-muted-foreground/50" disabled={!eSess||searching}/><Button size="sm" onClick={doSearch} disabled={!eSess||searching||!sq.trim()} className="h-8 w-8 p-0">{searching?<Loader2 className="w-3.5 h-3.5 animate-spin"/>:<Search className="w-3.5 h-3.5"/>}</Button></div>
              {sResults.length>0&&<div className="space-y-1 max-h-40 overflow-y-auto">{sResults.map((r,i)=><button key={i} onClick={()=>{const fn=(ns:FileTreeNode[],p:string):FileTreeNode|null=>{for(const n of ns){if(n.path===p)return n;if(n.children){const f=fn(n.children,p);if(f)return f;}}return null;};if(eSess){const nd=fn(eSess.structure,r.path);if(nd)loadFile(nd);}}} className="w-full text-right text-xs bg-muted/20 hover:bg-muted/40 rounded p-2 border border-border"><div className="font-medium text-foreground/80 truncate">{r.path}</div><div className="text-muted-foreground mt-0.5">{r.relevance}</div></button>)}</div>}
            </div>
            <div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl overflow-hidden flex flex-col flex-1 min-h-0">
              <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-muted/20 shrink-0"><FolderOpen className="w-3.5 h-3.5 text-amber-400"/><span className="text-xs font-medium">الملفات</span>{eMods.size>0&&<span className="mr-auto text-[10px] px-1.5 py-0.5 bg-yellow-500/20 text-yellow-300 rounded-full">{eMods.size}</span>}</div>
              {eSess&&<div className="px-2 pt-1.5 pb-1 border-b border-border/50 shrink-0"><div className="flex items-center gap-1 bg-muted/30 border border-border rounded-md px-1.5 py-0.5"><Search className="w-2.5 h-2.5 text-muted-foreground shrink-0"/><input value={editTreeFilter} onChange={e=>setEditTreeFilter(e.target.value)} placeholder="بحث..." className="flex-1 bg-transparent text-[11px] outline-none text-right placeholder:text-muted-foreground/50 min-w-0"/>{editTreeFilter&&<button onClick={()=>setEditTreeFilter("")} className="shrink-0"><X className="w-2.5 h-2.5 text-muted-foreground hover:text-foreground"/></button>}</div></div>}
              <div className="flex-1 overflow-y-auto p-1">{!eSess?<div className="flex flex-col items-center justify-center h-full py-10 text-muted-foreground text-sm"><Package className="w-8 h-8 mb-2 opacity-20"/><p>ارفع ملف</p></div>:eSess.structure.map((n,i)=><TNode key={i} node={n} onSelect={loadFile} sel={eNode?.path||""} mods={eMods} filter={editTreeFilter}/>)}</div>
            </div>
          </div>
          {/* Editor */}
          <div className="bg-card/70 backdrop-blur-sm border border-border rounded-2xl overflow-hidden flex flex-col min-h-0">
            <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-muted/20 shrink-0">
              <FileCode2 className="w-4 h-4 text-primary"/><span className="text-sm font-medium truncate flex-1">{eNode?.name||"اختر ملفاً"}</span>
              {eNode&&eMods.has(eNode.path)&&<span className="text-[10px] px-1.5 py-0.5 bg-yellow-500/20 text-yellow-300 rounded-full">معدّل</span>}
              {pending&&<div className="flex items-center gap-1 mr-auto"><Button size="sm" onClick={applyMod} className="h-6 text-xs gap-1 bg-emerald-600 px-2"><CheckCheck className="w-3 h-3"/>تطبيق</Button><Button size="sm" variant="ghost" onClick={()=>setPending(null)} className="h-6 w-6 p-0 text-red-400"><X className="w-3 h-3"/></Button></div>}
            </div>
            {eNode&&!eContent.startsWith("[")?<div className="flex-1 min-h-0"><Editor height="100%" language={lang("."+(eNode.name.split(".").pop()||""))} value={eContent} onChange={v=>v!==undefined&&setEContent(v)} theme={eNode.name.endsWith(".smali")?"smali-dark":"vs-dark"} beforeMount={registerSmaliLanguage} options={{fontSize:12,minimap:{enabled:false},wordWrap:"on",scrollBeyondLastLine:false,automaticLayout:true,readOnly:!eSess,lineNumbers:"on",folding:true,tabSize:2}}/></div>
            :<div className="flex-1 flex flex-col items-center justify-center text-muted-foreground"><FileCode2 className="w-10 h-10 mb-3 opacity-20"/><p className="text-sm">اختر ملفاً</p></div>}
          </div>
          {/* AI Panel */}
          <div className="flex flex-col gap-3 min-h-0">
            {/* Smart Modify */}
            <div className="bg-card/70 backdrop-blur-sm border border-primary/20 rounded-xl p-3 space-y-3 shrink-0">
              <div className="text-sm font-semibold flex items-center gap-1.5"><Sparkles className="w-4 h-4 text-primary"/>تعديل ذكي شامل</div>
              <p className="text-[10px] text-muted-foreground">اكتب ما تريد — AI يبحث ويعدل تلقائياً</p>
              <div className="flex flex-wrap gap-1.5">
                {([
                  ["إزالة كل القيود","text-red-300 border-red-500/30 bg-red-500/5 hover:bg-red-500/15"],
                  ["إزالة حماية Root","text-orange-300 border-orange-500/30 bg-orange-500/5 hover:bg-orange-500/15"],
                  ["تعطيل SSL Pinning","text-yellow-300 border-yellow-500/30 bg-yellow-500/5 hover:bg-yellow-500/15"],
                  ["إزالة حدود الاستخدام","text-emerald-300 border-emerald-500/30 bg-emerald-500/5 hover:bg-emerald-500/15"],
                  ["تمكين وضع التطوير","text-blue-300 border-blue-500/30 bg-blue-500/5 hover:bg-blue-500/15"],
                  ["تغيير نقطة API","text-violet-300 border-violet-500/30 bg-violet-500/5 hover:bg-violet-500/15"],
                ] as const).map(([q,cls])=>(
                  <button key={q} onClick={()=>setSmartInst(q)} className={`text-[10px] font-medium px-2 py-1 rounded-lg border transition-all hover:scale-105 ${cls}`}>{q}</button>
                ))}
              </div>
              <textarea value={smartInst} onChange={e=>setSmartInst(e.target.value)} placeholder="اكتب تعليماتك..." rows={3} className="w-full bg-muted/30 border border-border rounded-lg px-3 py-2 text-xs text-right placeholder:text-muted-foreground/50 resize-none" disabled={!eSess||smarting}/>
              <Button onClick={doSmartModify} disabled={!eSess||smarting||!smartInst.trim()} className="w-full gap-2 text-sm">{smarting?<><Loader2 className="w-4 h-4 animate-spin"/>يعدّل...</>:<><Zap className="w-4 h-4"/>تنفيذ</>}</Button>
            </div>
            {smartRes&&<div className="bg-card/70 backdrop-blur-sm border border-emerald-500/30 rounded-xl p-3 space-y-2 max-h-48 overflow-y-auto"><div className="text-xs font-semibold text-emerald-300">✅ {smartRes.filesModified} ملف</div><p className="text-xs text-muted-foreground">{smartRes.summary}</p>{smartRes.modifications.map((m,i)=><div key={i} className="text-[11px] bg-muted/20 rounded p-2"><div className="font-mono text-emerald-300/80">{m.filePath}</div><div className="text-muted-foreground">{m.explanation}</div></div>)}</div>}
            {eNode&&<div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-3 space-y-2"><div className="text-xs font-semibold flex items-center gap-1.5"><Bot className="w-3.5 h-3.5"/>تعديل هذا الملف</div><textarea value={aiInst} onChange={e=>setAiInst(e.target.value)} placeholder="تعليمات..." rows={2} className="w-full bg-muted/30 border border-border rounded-lg px-3 py-2 text-xs text-right placeholder:text-muted-foreground/50 resize-none" disabled={modifying}/><Button onClick={doAiModify} disabled={modifying||!aiInst.trim()} size="sm" className="w-full gap-2 text-xs">{modifying?<Loader2 className="w-3 h-3 animate-spin"/>:<Bot className="w-3 h-3"/>}تعديل</Button></div>}
            {eSess&&<div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-3 text-xs space-y-1.5 mt-auto"><div className="font-semibold text-muted-foreground">الجلسة</div><div className="flex justify-between"><span className="text-muted-foreground">معدّلة</span><span className="text-yellow-300">{eMods.size}</span></div><div className="flex justify-between"><span className="text-muted-foreground">وقت</span><span className={sessMins<5?"text-red-400":"text-emerald-400"}>{sessMins}م</span></div><div className="flex justify-between"><span className="text-muted-foreground">نوع</span><span className="text-emerald-300">{eType.toUpperCase()}</span></div></div>}
          </div>
        </div>
      </div>}

      {/* ═══ TAB 4: INTEL ═══ */}
      {tab==="intel"&&(
        <IntelTab
          sharedTree={sharedTree}
          intelTreeFilter={intelTreeFilter}
          intelSelNode={intelSelNode}
          intelSelContent={intelSelContent}
          intel={intel}
          intelLoading={intelLoading}
          irPat={irPat}
          irRes={irRes}
          irSearching={irSearching}
          irCat={irCat}
          iSess={iSess}
          aFile={aFile}
          eFile={eFile}
          vulnerabilities={res?.vulnerabilities}
          totalFilesLabel={String(res?.totalFiles||eSess?.fileCount||"")}
          TNode={TNode}
          ThreatGauge={ThreatGauge}
          VulnChart={VulnChart}
          lang={lang}
          registerSmaliLanguage={registerSmaliLanguage}
          doSharedNodeSelect={doSharedNodeSelect}
          doIntel={doIntel}
          doRegex={doRegex}
          setIntelTreeFilter={setIntelTreeFilter}
          setIntelSelNode={setIntelSelNode}
          setIntelSelContent={setIntelSelContent}
          setIrPat={setIrPat}
          setIrCat={setIrCat}
        />
      )}

      {/* ═══ TAB 5: FORENSICS ═══ */}
      {tab==="forensics"&&(
        <ForensicsTab
          sharedTree={sharedTree}
          forensicsTreeFilter={forensicsTreeFilter}
          forensicsSelNode={forensicsSelNode}
          forensicsSelContent={forensicsSelContent}
          iSess={iSess}
          aFile={aFile}
          eFile={eFile}
          fPanel={fPanel}
          fDecoded={fDecoded}
          fDecodedLoading={fDecodedLoading}
          fXref={fXref}
          fXrefLoading={fXrefLoading}
          fXrefQuery={fXrefQuery}
          fHierarchy={fHierarchy}
          fHierarchyLoading={fHierarchyLoading}
          fDataFlow={fDataFlow}
          fDataFlowLoading={fDataFlowLoading}
          fMethodSearch={fMethodSearch}
          fMethodLoading={fMethodLoading}
          fMethodQuery={fMethodQuery}
          fDiff={fDiff}
          fDiffLoading={fDiffLoading}
          fDiffFile1={fDiffFile1}
          fDiffFile2={fDiffFile2}
          fReportLoading={fReportLoading}
          fDiffRef1={fDiffRef1}
          fDiffRef2={fDiffRef2}
          totalFilesLabel={String(res?.totalFiles||eSess?.fileCount||"")}
          TNode={TNode}
          lang={lang}
          registerSmaliLanguage={registerSmaliLanguage}
          fmtB={fmtB}
          doSharedNodeSelect={doSharedNodeSelect}
          doDecodeStrings={doDecodeStrings}
          doXref={doXref}
          doHierarchy={doHierarchy}
          doDataFlow={doDataFlow}
          doMethodSearch={doMethodSearch}
          doDiff={doDiff}
          doForensicReport={doForensicReport}
          setForensicsTreeFilter={setForensicsTreeFilter}
          setForensicsSelNode={setForensicsSelNode}
          setForensicsSelContent={setForensicsSelContent}
          setFPanel={setFPanel}
          setFXrefQuery={setFXrefQuery}
          setFMethodQuery={setFMethodQuery}
          setFDiffFile1={setFDiffFile1}
          setFDiffFile2={setFDiffFile2}
        />
      )}

      {/* ══ TAB 6: CLOUD PENTEST ══ */}
      {tab==="cloudpen"&&(
        <CloudPentestTab
          cpResult={cpResult}
          cpLoading={cpLoading}
          cpFile={cpFile}
          cpActiveStep={cpActiveStep}
          cpStepsRevealed={cpStepsRevealed}
          cpExpanded={cpExpanded}
          cpShowReport={cpShowReport}
          cpFileRef={cpFileRef}
          doCloudPentestFull={doCloudPentestFull}
          setCpFile={setCpFile}
          setCpResult={setCpResult}
          setCpStepsRevealed={setCpStepsRevealed}
          setCpActiveStep={setCpActiveStep}
          setCpExpanded={setCpExpanded}
          setCpShowReport={setCpShowReport}
        />
      )}

    </div>
  </DashboardLayout>);
}
