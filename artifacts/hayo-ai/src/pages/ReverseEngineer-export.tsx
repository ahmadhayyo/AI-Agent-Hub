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
  Info, Lock, Unlock, ScanSearch, Package, Cpu,
  Shield, BookOpen, Wrench, Archive, FileJson,
  Search, Save, Hammer, Binary, AlertTriangle,
  Dot, CheckCheck, Undo2, Sparkles, Eye, Zap,
  GitBranch, Globe, Key, Terminal, Scan, Fingerprint,
  ToggleLeft, ToggleRight, Rocket,
  Keyboard, Database, Activity, TrendingUp, BarChart3, Code,
  Microscope, Network, FileSearch, Diff, Layers, FileOutput,
  ArrowUpDown, Braces, Hash, Link2, type LucideIcon,
} from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

// ═══ Types ═══
interface DecompiledFile { path:string; name:string; extension:string; size:number; content?:string; isBinary:boolean; }
interface FileTreeNode { name:string; path:string; type:"file"|"folder"; size?:number; children?:FileTreeNode[]; }
interface VulnerabilityFinding { severity:"critical"|"high"|"medium"|"low"|"info"; category:string; title:string; description:string; evidence:string[]; }
interface DecompileResult { success:boolean; fileType:string; totalFiles:number; totalSize:number; structure:FileTreeNode[]; files:DecompiledFile[]; manifest?:any; metadata?:any; downloadId?:string; error?:string; analysisAvailable:boolean; vulnerabilities?:VulnerabilityFinding[]; formatLabel?:string; }
interface EditSession { sessionId:string; structure:FileTreeNode[]; fileCount:number; apkToolAvailable:boolean; usedApkTool:boolean; fileType?:string; }
interface IntelReport { ssl:string[]; root:string[]; crypto:string[]; secrets:string[]; urls:string[]; summary:string; }
interface SmartModifyResult { modifications:Array<{filePath:string;explanation:string;originalSnippet:string;modifiedSnippet:string}>; summary:string; filesModified:number; }

// ═══ Constants ═══
const ALL_FORMATS = ["apk","exe","dll","msi","ex4","ex5","ipa","jar","aar","dex","so","wasm"] as const;
const ACCEPT_STR = ALL_FORMATS.map(f=>`.${f}`).join(",");
const FMT_ICON:Record<string,string> = {apk:"🤖",exe:"🖥️",dll:"⚙️",msi:"📦",ex4:"📈",ex5:"📊",ipa:"🍎",jar:"☕",aar:"🟢",dex:"🔵",so:"🔧",wasm:"🌐"};
const FMT_LABEL:Record<string,string> = {apk:"Android APK",exe:"Windows EXE",dll:"Windows DLL",msi:"Windows MSI",ex4:"MetaTrader 4",ex5:"MetaTrader 5",ipa:"iOS IPA",jar:"Java JAR",aar:"Android AAR",dex:"Dalvik DEX",so:"Linux SO/ELF",wasm:"WebAssembly"};
const DANGER_PERMS = new Set(["READ_CONTACTS","WRITE_CONTACTS","READ_SMS","SEND_SMS","READ_PHONE_STATE","CALL_PHONE","ACCESS_FINE_LOCATION","CAMERA","RECORD_AUDIO","READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE","USE_BIOMETRIC"]);

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

  // ══ TAB 2: CLONE ══
  const[cFile,setCFile]=useState<File|null>(null);
  const[cloning,setCloning]=useState(false);
  const[cOpts,setCOpts]=useState({removeAds:true,unlockPremium:true,removeTracking:false,removeLicenseCheck:true,changeAppName:"",changePackageName:"",customInstructions:""});
  const[cResult,setCResult]=useState<{modifications:string[];patchedFiles?:number;signed?:boolean;downloadUrl?:string;installCommand?:string;success?:boolean}|null>(null);

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

  // ═══ TAB 1 HANDLERS ═══
  const doDecompile=async()=>{
    if(!aFile)return;setDecomp(true);setRes(null);setAiText("");setSelNode(null);setSelContent("");
    const fd=new FormData();fd.append("file",aFile);
    try{
      const r=await fetchRE("/api/reverse/decompile",{method:"POST",body:fd});const d=await r.json();
      if(!r.ok){toast.error(d.error||"فشل التحليل");return;}
      setRes(d);if(d.downloadId)setDlId(d.downloadId);toast.success(`✅ ${d.totalFiles} ملف`);
      const fd2=new FormData();fd2.append("file",aFile);
      try{const r2=await fetchRE("/api/reverse/decompile-for-edit",{method:"POST",body:fd2});const d2=await r2.json();if(r2.ok&&d2.sessionId){setASessId(d2.sessionId);setESess(d2);setEType(d2.fileType||"apk");setEMods(new Set());setSessMins(30);toast.success("✅ الجلسة جاهزة — الاستخبارات والطب الشرعي والتحرير مرتبطة");}else{toast.error(d2.error||"فشل إنشاء جلسة التحرير");}}catch(e:any){toast.error(e.message||"فشل إنشاء جلسة التحرير");}
    }catch(e:any){toast.error(e.message);}finally{setDecomp(false);}
  };
  const doSelNode=(n:FileTreeNode)=>{setSelNode(n);setAiText("");setShowAi(false);if(res){const f=res.files.find(f=>f.path===n.path);if(f?.isBinary){setSelBinary(f);setSelContent("");}else{setSelBinary(null);setSelContent(f?.content||"لا محتوى");}}};
  const doAiAnalysis=async(type:string)=>{
    if(!selContent||selContent.startsWith("["))return;setAnalyzing(true);setShowAi(true);setAiText("");
    try{const r=await fetchRE("/api/reverse/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:selContent,fileName:selNode?.name,analysisType:type})});const d=await r.json();if(!r.ok){toast.error(d.error);setShowAi(false);return;}setAiText(d.analysis);}catch(e:any){toast.error(e.message);setShowAi(false);}finally{setAnalyzing(false);}
  };

  // ═══ TAB 2 HANDLERS ═══
  const doClone=async()=>{
    if(!cFile)return;setCloning(true);setCResult(null);
    const fd=new FormData();fd.append("file",cFile);
    fd.append("removeAds",String(cOpts.removeAds));fd.append("unlockPremium",String(cOpts.unlockPremium));
    fd.append("removeTracking",String(cOpts.removeTracking));fd.append("removeLicenseCheck",String(cOpts.removeLicenseCheck));
    if(cOpts.changeAppName)fd.append("changeAppName",cOpts.changeAppName);
    if(cOpts.changePackageName)fd.append("changePackageName",cOpts.changePackageName);
    if(cOpts.customInstructions)fd.append("customInstructions",cOpts.customInstructions);
    try{
      const r=await fetchRE("/api/reverse/clone",{method:"POST",body:fd});
      if(!r.ok){const d=await r.json();setCResult({modifications:d.modifications||[],success:false});toast.error(d.error||"فشل");return;}
      let mods:string[]=[];try{mods=JSON.parse(decodeURIComponent(r.headers.get("X-Modifications")||"[]"));}catch{}
      const signed=r.headers.get("X-APK-Signed")==="true";
      const patchedFiles=parseInt(r.headers.get("X-Patched-Files")||"0",10)||mods.length;
      const blob=await r.blob();const dlUrl=URL.createObjectURL(blob);const a=document.createElement("a");a.href=dlUrl;
      const ext=cFile.name.split(".").pop()?.toLowerCase();
      const bn=cFile.name.replace(/\.[^.]+$/,"");a.download=ext==="apk"?`cloned-${bn}.apk`:`cloned-${bn}.zip`;a.click();
      setCResult({modifications:mods,patchedFiles,signed,downloadUrl:dlUrl,installCommand:ext==="apk"?"adb install -r cloned-"+cFile.name:undefined,success:true});
      toast.success(signed?"🎉 استنساخ + توقيع — جاهز!":"✅ تم الاستنساخ");
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

  const tabs:{id:Tab;label:string;icon:any}[]=[{id:"analyze",label:"تحليل",icon:Eye},{id:"clone",label:"استنساخ",icon:GitBranch},{id:"edit",label:"تحرير & بناء",icon:Hammer},{id:"intel",label:"استخبارات",icon:Fingerprint},{id:"forensics",label:"طب شرعي",icon:Microscope},{id:"cloudpen",label:"اختراق سحابي",icon:Database}];

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
      {tab==="analyze"&&<div className="flex-1 grid grid-cols-1 lg:grid-cols-[280px_240px_1fr] gap-4 min-h-0">
        {/* Upload + Info */}
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-2 text-xs text-muted-foreground bg-emerald-500/5 border border-emerald-500/20 rounded-lg px-3 py-2"><Info className="w-3.5 h-3.5 text-emerald-400 shrink-0"/><span>تفكيك <b className="text-emerald-300">5</b> · تحليل <b className="text-emerald-300">3</b> نقاط</span></div>
          <div className={`border-2 border-dashed rounded-2xl p-5 text-center cursor-pointer transition-all ${drag?"border-emerald-400 bg-emerald-500/10":"border-border hover:border-emerald-400/50"}`} onDragOver={e=>{e.preventDefault();setDrag(true);}} onDragLeave={()=>setDrag(false)} onDrop={e=>{e.preventDefault();setDrag(false);const f=e.dataTransfer.files[0];if(f&&valid(f)){setAFile(f);setRes(null);}}} onClick={()=>fRef.current?.click()}>
            <input ref={fRef} type="file" accept={ACCEPT_STR} className="hidden" onChange={e=>{const f=e.target.files?.[0];if(f&&valid(f)){setAFile(f);setRes(null);}}}/>
            {aFile?<div className="space-y-2"><div className="text-3xl">{FMT_ICON[aFile.name.split(".").pop()?.toLowerCase()||""]||"📦"}</div><p className="font-medium text-sm truncate">{aFile.name}</p><p className="text-xs text-muted-foreground">{fmtB(aFile.size)}</p><button onClick={e=>{e.stopPropagation();setAFile(null);setRes(null);}} className="text-xs text-red-400"><X className="w-3 h-3 inline"/>تغيير</button></div>
            :<div className="space-y-2"><Upload className="w-8 h-8 mx-auto text-muted-foreground"/><p className="text-sm font-medium">اسحب أو انقر</p><p className="text-[10px] text-muted-foreground">{ALL_FORMATS.map(f=>f.toUpperCase()).join(" · ")}</p></div>}
          </div>
          {aFile&&!res&&!decomp&&<Button onClick={doDecompile} className="w-full gap-2 bg-emerald-600 hover:bg-emerald-700 py-5"><Binary className="w-4 h-4"/>تفكيك</Button>}
          {decomp&&<ProgressSteps step={decompStep}/>}
          {res&&<div className="space-y-2">
            {/* Stats header */}
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0"/>
              <span className="text-sm font-bold text-emerald-300">اكتمل التفكيك</span>
              {dlId&&<Button size="sm" variant="outline" onClick={()=>window.open(`/api/reverse/download/${dlId}`,"_blank")} className="mr-auto h-7 text-[10px] gap-1 border-emerald-500/30"><Archive className="w-3 h-3"/>ZIP</Button>}
            </div>
            {/* 4 animated stat cards */}
            <div className="grid grid-cols-2 gap-1.5">
              {([
                {icon:Database,  label:"الملفات",  value:String(res.totalFiles),     color:"text-emerald-300",bg:"from-emerald-500/10 to-emerald-500/5",border:"border-emerald-500/25",delay:0},
                {icon:BarChart3, label:"الحجم",    value:fmtB(res.totalSize),         color:"text-cyan-300",   bg:"from-cyan-500/10 to-cyan-500/5",   border:"border-cyan-500/25",   delay:80},
                {icon:FileCode2, label:"الصيغة",   value:(res.formatLabel||res.fileType||"—").toUpperCase(), color:"text-blue-300",bg:"from-blue-500/10 to-blue-500/5",border:"border-blue-500/25",delay:160},
                {icon:Sparkles, label:"نموذج AI", value:res.metadata?.aiModelUsed?res.metadata.aiModelUsed.replace("claude-","").replace("gpt-","GPT-").slice(0,10):"—",color:"text-violet-300",bg:"from-violet-500/10 to-violet-500/5",border:"border-violet-500/25",delay:240},
              ]).map(({icon:Icon,label,value,color,bg,border,delay})=>(
                <div key={label}
                  className={`bg-gradient-to-br ${bg} border ${border} rounded-xl p-2.5 text-center transition-all duration-500`}
                  style={{
                    opacity: statsAnim?1:0,
                    transform: statsAnim?"translateY(0)":"translateY(8px)",
                    transitionDelay:`${delay}ms`,
                  }}>
                  <Icon className={`w-3.5 h-3.5 mx-auto mb-1 ${color} opacity-70`}/>
                  <div className={`text-base font-black ${color} leading-tight truncate`}>{value}</div>
                  <div className="text-[9px] text-muted-foreground mt-0.5">{label}</div>
                </div>
              ))}
            </div>
          </div>}
          {res&&aSessId&&<div className="bg-gradient-to-br from-cyan-500/10 to-violet-500/10 border border-cyan-500/30 rounded-xl p-3 space-y-2 animate-in fade-in slide-in-from-top-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-cyan-300"><Zap className="w-4 h-4"/>الملف جاهز للتحليل المتقدم</div>
            <div className="grid grid-cols-2 gap-2">
              <button onClick={()=>{setTab("intel");setTimeout(()=>doIntel(),300);}} className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 transition-all text-xs font-medium"><Fingerprint className="w-4 h-4"/>استخبارات تلقائية</button>
              <button onClick={()=>{setTab("forensics");setTimeout(()=>doDecodeStrings(),300);}} className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-violet-500/10 border border-violet-500/30 text-violet-300 hover:bg-violet-500/20 transition-all text-xs font-medium"><Microscope className="w-4 h-4"/>طب شرعي تلقائي</button>
            </div>
            <button onClick={async()=>{toast.info("جاري التحليل الشامل...");setTab("intel");setTimeout(async()=>{await doIntel();setTab("forensics");setTimeout(()=>doDecodeStrings(),300);},300);}} className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-gradient-to-r from-cyan-600/80 to-violet-600/80 text-white hover:from-cyan-500 hover:to-violet-500 transition-all text-xs font-bold"><Sparkles className="w-4 h-4"/>تحليل تلقائي شامل (استخبارات + طب شرعي)</button>
          </div>}
          {res?.manifest?.permissions?.length>0&&<div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-3 space-y-2"><div className="flex items-center gap-2 text-sm font-semibold"><FileJson className="w-4 h-4 text-blue-400"/>صلاحيات</div><div className="max-h-32 overflow-y-auto space-y-0.5">{res.manifest.permissions.map((p:string)=><div key={p} className="flex items-center gap-1.5 text-xs">{DANGER_PERMS.has(p)?<Unlock className="w-3 h-3 text-red-400"/>:<Lock className="w-3 h-3 text-muted-foreground"/>}<span className={DANGER_PERMS.has(p)?"text-red-300":"text-muted-foreground"}>{p}</span></div>)}</div></div>}
          {res?.vulnerabilities&&res.vulnerabilities.length>0&&<VPanel findings={res.vulnerabilities}/>}
        </div>
        {/* Tree */}
        <div className="bg-card/70 backdrop-blur-sm border border-border rounded-2xl overflow-hidden flex flex-col">
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border bg-muted/20"><FolderOpen className="w-4 h-4 text-amber-400"/><span className="text-sm font-medium">الملفات</span>{res&&<span className="mr-auto text-xs text-muted-foreground">{res.totalFiles}</span>}</div>
          {res&&<div className="px-2 pt-2 pb-1 border-b border-border/50"><div className="flex items-center gap-1.5 bg-muted/30 border border-border rounded-lg px-2 py-1"><Search className="w-3 h-3 text-muted-foreground shrink-0"/><input value={treeFilter} onChange={e=>setTreeFilter(e.target.value)} placeholder="بحث في الملفات..." className="flex-1 bg-transparent text-xs outline-none text-right placeholder:text-muted-foreground/50 min-w-0"/>{treeFilter&&<button onClick={()=>setTreeFilter("")} className="shrink-0"><X className="w-3 h-3 text-muted-foreground hover:text-foreground"/></button>}</div></div>}
          <div className="flex-1 overflow-y-auto p-1">{!res?<div className="flex flex-col items-center justify-center h-full py-12 text-muted-foreground text-sm"><FolderOpen className="w-10 h-10 mb-2 opacity-20"/><p>ارفع ملفاً</p></div>:res.structure.map((n,i)=><TNode key={i} node={n} onSelect={doSelNode} sel={selNode?.path||""} filter={treeFilter}/>)}</div>
        </div>
        {/* Viewer */}
        <div className="flex flex-col gap-3 min-h-0">
          <div className="bg-card/70 backdrop-blur-sm border border-border rounded-2xl overflow-hidden flex flex-col" style={{minHeight:"300px",flex:1}}>
            <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-muted/20 shrink-0">
              <FileCode2 className="w-4 h-4 text-primary"/><span className="text-sm font-medium truncate flex-1">{selNode?.name||"اختر ملفاً"}</span>
              {selContent&&!selContent.startsWith("[")&&<div className="flex items-center gap-1">
                <DropdownMenu><DropdownMenuTrigger asChild><Button size="sm" variant="outline" disabled={analyzing} className="gap-1.5 h-7 px-2 text-xs border-primary/30"><Bot className="w-3.5 h-3.5 text-primary"/>AI<ChevronDown className="w-3 h-3"/></Button></DropdownMenuTrigger><DropdownMenuContent align="start" className="w-40 z-50"><DropdownMenuItem onClick={()=>doAiAnalysis("explain")} className="gap-2 text-xs cursor-pointer"><BookOpen className="w-3 h-3"/>شرح</DropdownMenuItem><DropdownMenuItem onClick={()=>doAiAnalysis("security")} className="gap-2 text-xs cursor-pointer"><Shield className="w-3 h-3 text-red-400"/>أمني</DropdownMenuItem><DropdownMenuItem onClick={()=>doAiAnalysis("logic")} className="gap-2 text-xs cursor-pointer"><Wrench className="w-3 h-3 text-blue-400"/>منطق</DropdownMenuItem><DropdownMenuItem onClick={()=>doAiAnalysis("full")} className="gap-2 text-xs cursor-pointer"><Bot className="w-3 h-3 text-primary"/>شامل</DropdownMenuItem></DropdownMenuContent></DropdownMenu>
                <Button size="sm" variant="ghost" onClick={()=>{navigator.clipboard.writeText(selContent);toast.success("نسخ");}} className="h-7 w-7 p-0"><Copy className="w-3.5 h-3.5"/></Button>
                <Button size="sm" variant="ghost" onClick={()=>{const b=new Blob([selContent],{type:"text/plain"});const u=URL.createObjectURL(b);const a=document.createElement("a");a.href=u;a.download=selNode?.name||"file";a.click();}} className="h-7 w-7 p-0"><Download className="w-3.5 h-3.5"/></Button>
              </div>}
            </div>
            <div className="flex-1 min-h-0">{selBinary
              ?<BinaryHexViewer file={selBinary} sessionId={aSessId||eSess?.sessionId}/>
              :selContent
              ?<Editor
                  height="100%"
                  language={lang(selNode?.name?.includes(".")?"."+selNode.name.split(".").pop()!:"")}
                  value={selContent}
                  theme={selNode?.name?.endsWith(".smali")?"smali-dark":"vs-dark"}
                  beforeMount={registerSmaliLanguage}
                  options={{
                    readOnly:true,
                    minimap:{enabled:false},
                    fontSize:12,
                    wordWrap:"on",
                    scrollBeyondLastLine:false,
                    renderLineHighlight:"none",
                    lineNumbers:"on",
                    folding:true,
                    automaticLayout:true,
                  }}
                />
              :<div className="flex flex-col items-center justify-center h-full p-6 gap-4 text-center">
                  <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 border border-emerald-500/30 flex items-center justify-center"><FileCode2 className="w-7 h-7 text-emerald-400 opacity-60"/></div>
                  <div><p className="text-sm font-semibold text-muted-foreground">اختر ملفاً من الشجرة</p><p className="text-[11px] text-muted-foreground/50 mt-1">لعرض الكود مع تلوين صياغي كامل</p></div>
                  <div className="w-full max-w-[220px] space-y-1.5">
                    {([
                      [Database,"قراءة البنية الداخلية","text-emerald-400"],
                      [Activity,"تحليل السلوك والأذونات","text-blue-400"],
                      [TrendingUp,"كشف الثغرات الأمنية","text-orange-400"],
                    ] as const).map(([Icon,label,cls])=>(
                      <div key={label} className="flex items-center gap-2 bg-muted/20 rounded-lg px-3 py-2 border border-border/50">
                        <Icon className={`w-3.5 h-3.5 shrink-0 ${cls}`}/>
                        <span className="text-[11px] text-muted-foreground">{label}</span>
                      </div>
                    ))}
                  </div>
                </div>}</div>
          </div>
          {showAi&&<div className="bg-card/70 backdrop-blur-sm border border-primary/30 rounded-2xl overflow-hidden flex flex-col" style={{maxHeight:"380px"}}><div className="flex items-center gap-2 px-3 py-2.5 border-b border-border bg-primary/5 shrink-0"><Bot className="w-4 h-4 text-primary"/><span className="text-sm font-medium">AI</span><Button size="sm" variant="ghost" onClick={()=>setShowAi(false)} className="mr-auto h-6 w-6 p-0"><X className="w-3 h-3"/></Button></div><div className="flex-1 overflow-y-auto p-4 text-sm leading-relaxed">{analyzing?<div className="flex items-center gap-3 justify-center py-12 text-muted-foreground"><Loader2 className="w-5 h-5 animate-spin text-primary"/>يحلل...</div>:<div className="whitespace-pre-wrap">{aiText}</div>}</div></div>}
        </div>
      </div>}

      {/* ═══ TAB 2: CLONE ═══ */}
      {tab==="clone"&&<div className="flex-1 flex flex-col gap-4 max-w-3xl mx-auto w-full">
        <div className="text-center space-y-2"><div className="w-14 h-14 mx-auto rounded-2xl bg-gradient-to-br from-violet-500/30 to-pink-500/30 flex items-center justify-center border border-violet-500/30"><GitBranch className="w-7 h-7 text-violet-400"/></div><h2 className="text-xl font-bold">App Cloner</h2><p className="text-sm text-muted-foreground">تفكيك → تعديل → توقيع → بناء تلقائي</p></div>
        <div className="border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer hover:border-violet-400/50 transition-all" onClick={()=>cfRef.current?.click()}>
          <input ref={cfRef} type="file" accept={ACCEPT_STR} className="hidden" onChange={e=>{const f=e.target.files?.[0];if(f&&valid(f))setCFile(f);}}/>
          {cFile?<div className="space-y-2"><span className="text-3xl">{FMT_ICON[cFile.name.split(".").pop()?.toLowerCase()||""]||"📦"}</span><p className="font-medium">{cFile.name}</p><p className="text-sm text-muted-foreground">{fmtB(cFile.size)}</p><button onClick={e=>{e.stopPropagation();setCFile(null);setCResult(null);}} className="text-xs text-red-400"><X className="w-3 h-3 inline"/>تغيير</button></div>
          :<div className="space-y-2"><Upload className="w-8 h-8 mx-auto text-muted-foreground"/><p className="text-sm">اسحب أو انقر</p><p className="text-xs text-muted-foreground">{ALL_FORMATS.map(f=>f.toUpperCase()).join(" · ")}</p></div>}
        </div>
        <div className="grid grid-cols-2 gap-3">
          {([["removeAds","إزالة الإعلانات","🚫","AdMob, Facebook, Unity"],["unlockPremium","فتح المدفوع","🔓","isPremium, isSubscribed"],["removeTracking","إزالة التتبع","📡","Firebase, Analytics"],["removeLicenseCheck","تجاوز الرخصة","🔑","checkLicense, verifySignature"]] as const).map(([k,l,ic,d])=><button key={k} onClick={()=>setCOpts(p=>({...p,[k]:!p[k as keyof typeof p]}))} className={`p-3 rounded-xl border text-right transition-all ${cOpts[k as keyof typeof cOpts]?"bg-violet-500/10 border-violet-500/40 text-violet-300":"bg-card/70 backdrop-blur-sm border-border text-muted-foreground hover:border-violet-500/30"}`}><div className="flex items-center gap-2"><span className="text-lg">{ic}</span><span className="font-medium text-sm">{l}</span><span className="mr-auto">{cOpts[k as keyof typeof cOpts]?<ToggleRight className="w-5 h-5 text-violet-400"/>:<ToggleLeft className="w-5 h-5"/>}</span></div><p className="text-[10px] mt-1 opacity-60">{d}</p></button>)}
        </div>
        <div className="grid grid-cols-2 gap-3">
          <input value={cOpts.changeAppName} onChange={e=>setCOpts(p=>({...p,changeAppName:e.target.value}))} placeholder="اسم جديد (اختياري)" className="bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm text-right placeholder:text-muted-foreground/50 focus:outline-none focus:border-violet-500/50"/>
          <input value={cOpts.changePackageName} onChange={e=>setCOpts(p=>({...p,changePackageName:e.target.value}))} placeholder="حزمة جديدة (اختياري)" className="bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm text-right placeholder:text-muted-foreground/50 focus:outline-none focus:border-violet-500/50 font-mono"/>
        </div>
        <textarea value={cOpts.customInstructions} onChange={e=>setCOpts(p=>({...p,customInstructions:e.target.value}))} placeholder="تعليمات إضافية للذكاء الاصطناعي..." rows={2} className="bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm text-right placeholder:text-muted-foreground/50 resize-none"/>
        <Button onClick={doClone} disabled={!cFile||cloning} className="w-full gap-2 py-6 text-base bg-gradient-to-r from-violet-600 to-pink-600 hover:from-violet-500 hover:to-pink-500">{cloning?<><Loader2 className="w-5 h-5 animate-spin"/>جاري الاستنساخ...</>:<><Rocket className="w-5 h-5"/>استنساخ الآن</>}</Button>
        {cResult&&!cResult.success&&<div className="bg-card/70 backdrop-blur-sm border border-red-500/20 rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-red-400"/><span className="text-sm font-bold text-red-300">فشل الاستنساخ</span></div>
          {cResult.modifications.length>0&&<div className="max-h-40 overflow-y-auto space-y-1">{cResult.modifications.map((m:string,i:number)=><div key={i} className="text-xs bg-muted/20 rounded px-2 py-1 text-muted-foreground">{m}</div>)}</div>}
        </div>}
        {cResult&&cResult.success&&<div className="bg-card/70 backdrop-blur-sm border border-emerald-500/20 rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2"><CheckCircle2 className="w-5 h-5 text-emerald-400"/><span className="text-sm font-bold text-emerald-300">استنساخ ناجح</span></div>
          <div className="grid grid-cols-3 gap-2">
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-2 text-center"><div className="text-lg font-bold text-emerald-300">{cResult.modifications.length}</div><div className="text-[10px] text-muted-foreground">تعديل</div></div>
            <div className="bg-violet-500/10 border border-violet-500/30 rounded-lg p-2 text-center"><div className="text-lg font-bold text-violet-300">{cResult.patchedFiles||0}</div><div className="text-[10px] text-muted-foreground">ملف معدّل</div></div>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-2 text-center"><div className="text-lg font-bold text-blue-300">{cResult.signed?"موقّع":"غير موقّع"}</div><div className="text-[10px] text-muted-foreground">التوقيع</div></div>
          </div>
          <div className="text-xs font-semibold text-muted-foreground">سجل التعديلات:</div>
          <div className="max-h-56 overflow-y-auto space-y-1.5">{cResult.modifications.map((m:string,i:number)=><div key={i} className="text-xs bg-muted/20 rounded-lg px-3 py-2 flex items-start gap-2 border border-border/50"><span className="text-emerald-400 shrink-0 mt-0.5">{m.includes("إزالة")?"🗑️":m.includes("تغيير")?"✏️":m.includes("تعطيل")?"⛔":m.includes("توقيع")?"🔏":"✅"}</span><span className="text-muted-foreground">{m}</span></div>)}</div>
          {cResult.downloadUrl&&<a href={cResult.downloadUrl} download className="flex items-center justify-center gap-2 w-full py-3 rounded-xl bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-semibold text-sm transition-all"><Download className="w-4 h-4"/>تحميل الملف المعدّل</a>}
          {cResult.installCommand&&<div className="bg-muted/30 border border-border rounded-lg p-2 font-mono text-xs text-muted-foreground"><span className="text-emerald-400">$</span> {cResult.installCommand}</div>}
        </div>}
      </div>}

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
      {tab==="intel"&&<div className="flex-1 grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-4 min-h-0">
        {/* File Tree Sidebar */}
        <div className="bg-card/70 backdrop-blur-sm border border-cyan-500/20 rounded-2xl overflow-hidden flex flex-col">
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border bg-cyan-500/5"><FolderOpen className="w-4 h-4 text-cyan-400"/><span className="text-sm font-medium">الملفات</span>{sharedTree.length>0&&<span className="mr-auto text-xs text-muted-foreground">{res?.totalFiles||eSess?.fileCount||""}</span>}</div>
          {sharedTree.length>0&&<div className="px-2 pt-2 pb-1 border-b border-border/50"><div className="flex items-center gap-1.5 bg-muted/30 border border-border rounded-lg px-2 py-1"><Search className="w-3 h-3 text-muted-foreground shrink-0"/><input value={intelTreeFilter} onChange={e=>setIntelTreeFilter(e.target.value)} placeholder="بحث..." className="flex-1 bg-transparent text-xs outline-none text-right placeholder:text-muted-foreground/50 min-w-0"/>{intelTreeFilter&&<button onClick={()=>setIntelTreeFilter("")} className="shrink-0"><X className="w-3 h-3 text-muted-foreground hover:text-foreground"/></button>}</div></div>}
          <div className="flex-1 overflow-y-auto p-1">{sharedTree.length===0?<div className="flex flex-col items-center justify-center h-full py-8 text-muted-foreground text-xs"><FolderOpen className="w-8 h-8 mb-2 opacity-20"/><p>فكّك ملفاً أولاً</p></div>:sharedTree.map((n,i)=><TNode key={i} node={n} onSelect={n2=>doSharedNodeSelect(n2,"intel")} sel={intelSelNode?.path||""} filter={intelTreeFilter}/>)}</div>
        </div>
        {/* Intel Content */}
        <div className="flex flex-col gap-4 min-h-0 overflow-y-auto">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/20"><Fingerprint className="w-5 h-5 text-cyan-400"/></div>
            <div><h2 className="text-lg font-bold">لوحة الاستخبارات</h2><p className="text-xs text-muted-foreground">APIs · URLs · مفاتيح · تشفير · بيانات حساسة</p></div>
            <Button onClick={doIntel} disabled={intelLoading||!iSess} size="sm" className="mr-auto gap-2 bg-cyan-600 hover:bg-cyan-700">{intelLoading?<Loader2 className="w-4 h-4 animate-spin"/>:<Scan className="w-4 h-4"/>}فحص</Button>
          </div>
          {iSess&&<div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-xs">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0"/>
            <span className="text-emerald-300 font-medium">ملف محمّل</span>
            {aFile&&<span className="text-muted-foreground truncate max-w-[200px]">{aFile.name}</span>}
            {eFile&&!aFile&&<span className="text-muted-foreground truncate max-w-[200px]">{eFile.name}</span>}
            <span className="text-muted-foreground/50 font-mono mr-auto">{iSess.slice(0,8)}…</span>
          </div>}
          {!iSess&&<div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-4 text-center text-sm text-amber-300"><AlertTriangle className="w-5 h-5 mx-auto mb-2"/>افتح ملفاً في التحليل أو التحرير أولاً</div>}
          {intelSelNode&&<div className="bg-card/70 backdrop-blur-sm border border-cyan-500/30 rounded-xl overflow-hidden" style={{maxHeight:"300px"}}>
            <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-muted/20"><FileCode2 className="w-4 h-4 text-cyan-400"/><span className="text-sm font-medium truncate">{intelSelNode.name}</span><button onClick={()=>{setIntelSelNode(null);setIntelSelContent("");}} className="mr-auto"><X className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground"/></button></div>
            <Editor height="250px" language={lang("."+intelSelNode.name.split(".").pop())} value={intelSelContent} theme={intelSelNode.name.endsWith(".smali")?"smali-dark":"vs-dark"} beforeMount={registerSmaliLanguage} options={{readOnly:true,minimap:{enabled:false},fontSize:12,lineNumbers:"on",scrollBeyondLastLine:false}}/>
          </div>}
          {(res?.vulnerabilities||intel)&&<div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <ThreatGauge vulns={res?.vulnerabilities}/>
            <VulnChart vulns={res?.vulnerabilities}/>
          </div>}
          {intel&&<div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {([["ssl","SSL/TLS",Lock,"text-red-400 bg-red-500/10 border-red-500/30"],["root","Root",Terminal,"text-orange-400 bg-orange-500/10 border-orange-500/30"],["crypto","Crypto",Key,"text-yellow-400 bg-yellow-500/10 border-yellow-500/30"],["secrets","Secrets",Fingerprint,"text-purple-400 bg-purple-500/10 border-purple-500/30"],["urls","URLs",Globe,"text-blue-400 bg-blue-500/10 border-blue-500/30"]] as const).map(([k,l,Ic,cls])=><button key={k} onClick={()=>{setIrCat(k);doRegex("",k);}} className={`p-3 rounded-xl border transition-all hover:scale-105 ${cls}`}><Ic className="w-5 h-5 mx-auto mb-1"/><div className="text-2xl font-bold">{intel[k as keyof IntelReport]?.length||0}</div><div className="text-xs font-medium">{l}</div></button>)}
          </div>}
          <div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-3 space-y-2">
            <div className="flex items-center gap-2"><Search className="w-4 h-4 text-cyan-400"/><span className="text-sm font-semibold">بحث Regex</span></div>
            <div className="flex gap-2"><input value={irPat} onChange={e=>setIrPat(e.target.value)} onKeyDown={e=>e.key==="Enter"&&doRegex()} placeholder="api[_-]?key|password" className="flex-1 bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm font-mono text-right placeholder:text-muted-foreground/50" disabled={!iSess||irSearching}/><Button onClick={()=>doRegex()} disabled={!iSess||irSearching||!irPat.trim()}>{irSearching?<Loader2 className="w-4 h-4 animate-spin"/>:<Search className="w-4 h-4"/>}</Button></div>
            <div className="flex flex-wrap gap-1.5">{["SSL","Root","Crypto","Secrets","URLs"].map(c=><button key={c} onClick={()=>{setIrCat(c.toLowerCase());doRegex("",c.toLowerCase());}} className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${irCat===c.toLowerCase()?"bg-cyan-500/20 border-cyan-500/40 text-cyan-300":"bg-muted/30 border-border text-muted-foreground hover:text-foreground"}`}>{c}</button>)}</div>
          </div>
          {irRes.length>0&&<div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl overflow-hidden">
            <div className="px-3 py-2 border-b border-border bg-muted/20 flex items-center gap-2"><Terminal className="w-3.5 h-3.5 text-cyan-400"/><span className="text-xs font-semibold">{irRes.length} نتيجة</span></div>
            <div className="max-h-96 overflow-y-auto divide-y divide-border/50">{irRes.map((r,i)=><div key={i} className="px-3 py-2 hover:bg-muted/10"><div className="flex items-center gap-2 text-xs"><span className="text-cyan-400 font-mono truncate max-w-[200px]">{r.filePath}</span><span className="text-muted-foreground">:{r.line}</span><span className="mr-auto text-emerald-400 font-medium">{r.match}</span></div><div className="text-[11px] font-mono text-muted-foreground mt-0.5 truncate">{r.context}</div></div>)}</div>
          </div>}
          {intel&&irCat&&(intel[irCat as keyof IntelReport] as string[])?.length>0&&<div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-3 space-y-2 max-h-64 overflow-y-auto"><div className="text-sm font-semibold">{irCat.toUpperCase()}</div>{(intel[irCat as keyof IntelReport] as string[]).map((item,i)=><div key={i} className="text-xs font-mono bg-muted/20 rounded px-2 py-1 truncate text-muted-foreground">{item}</div>)}</div>}
        </div>
      </div>}

      {/* ═══ TAB 5: FORENSICS ═══ */}
      {tab==="forensics"&&<div className="flex-1 grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-4 min-h-0">
        {/* File Tree Sidebar */}
        <div className="bg-card/70 backdrop-blur-sm border border-violet-500/20 rounded-2xl overflow-hidden flex flex-col">
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border bg-violet-500/5"><FolderOpen className="w-4 h-4 text-violet-400"/><span className="text-sm font-medium">الملفات</span>{sharedTree.length>0&&<span className="mr-auto text-xs text-muted-foreground">{res?.totalFiles||eSess?.fileCount||""}</span>}</div>
          {sharedTree.length>0&&<div className="px-2 pt-2 pb-1 border-b border-border/50"><div className="flex items-center gap-1.5 bg-muted/30 border border-border rounded-lg px-2 py-1"><Search className="w-3 h-3 text-muted-foreground shrink-0"/><input value={forensicsTreeFilter} onChange={e=>setForensicsTreeFilter(e.target.value)} placeholder="بحث..." className="flex-1 bg-transparent text-xs outline-none text-right placeholder:text-muted-foreground/50 min-w-0"/>{forensicsTreeFilter&&<button onClick={()=>setForensicsTreeFilter("")} className="shrink-0"><X className="w-3 h-3 text-muted-foreground hover:text-foreground"/></button>}</div></div>}
          <div className="flex-1 overflow-y-auto p-1">{sharedTree.length===0?<div className="flex flex-col items-center justify-center h-full py-8 text-muted-foreground text-xs"><FolderOpen className="w-8 h-8 mb-2 opacity-20"/><p>فكّك ملفاً أولاً</p></div>:sharedTree.map((n,i)=><TNode key={i} node={n} onSelect={n2=>doSharedNodeSelect(n2,"forensics")} sel={forensicsSelNode?.path||""} filter={forensicsTreeFilter}/>)}</div>
        </div>
        {/* Forensics Content */}
        <div className="flex flex-col gap-4 min-h-0 overflow-y-auto">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-gradient-to-br from-violet-500/20 to-pink-500/20 border border-violet-500/20"><Microscope className="w-5 h-5 text-violet-400"/></div>
          <div><h2 className="text-lg font-bold">مختبر الطب الشرعي</h2><p className="text-xs text-muted-foreground">تحليل متقدم · فك تشفير · تتبع مراجع · هرمية الكلاسات · تدفق البيانات</p></div>
          <Button onClick={doForensicReport} disabled={fReportLoading||!iSess} size="sm" className="mr-auto gap-2 bg-violet-600 hover:bg-violet-700">{fReportLoading?<Loader2 className="w-4 h-4 animate-spin"/>:<FileOutput className="w-4 h-4"/>}تصدير تقرير</Button>
        </div>

        {iSess&&<div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-xs">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0"/>
          <span className="text-emerald-300 font-medium">ملف محمّل</span>
          {aFile&&<span className="text-muted-foreground truncate max-w-[200px]">{aFile.name}</span>}
          {eFile&&!aFile&&<span className="text-muted-foreground truncate max-w-[200px]">{eFile.name}</span>}
          <span className="text-muted-foreground/50 font-mono mr-auto">{iSess.slice(0,8)}…</span>
          <Button onClick={async()=>{toast.info("تحليل تلقائي...");await doDecodeStrings();doHierarchy();}} disabled={fDecodedLoading||fHierarchyLoading} size="sm" variant="outline" className="gap-1 h-7 text-[10px] border-violet-500/30 text-violet-300">{fDecodedLoading||fHierarchyLoading?<Loader2 className="w-3 h-3 animate-spin"/>:<Zap className="w-3 h-3"/>}تحليل تلقائي</Button>
        </div>}
        {!iSess&&<div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-6 text-center text-sm text-amber-300"><AlertTriangle className="w-6 h-6 mx-auto mb-2"/>افتح ملفاً في التحليل أو التحرير أولاً لتفعيل أدوات الطب الشرعي</div>}
        {forensicsSelNode&&<div className="bg-card/70 backdrop-blur-sm border border-violet-500/30 rounded-xl overflow-hidden" style={{maxHeight:"300px"}}>
          <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-muted/20"><FileCode2 className="w-4 h-4 text-violet-400"/><span className="text-sm font-medium truncate">{forensicsSelNode.name}</span><button onClick={()=>{setForensicsSelNode(null);setForensicsSelContent("");}} className="mr-auto"><X className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground"/></button></div>
          <Editor height="250px" language={lang("."+forensicsSelNode.name.split(".").pop())} value={forensicsSelContent} theme={forensicsSelNode.name.endsWith(".smali")?"smali-dark":"vs-dark"} beforeMount={registerSmaliLanguage} options={{readOnly:true,minimap:{enabled:false},fontSize:12,lineNumbers:"on",scrollBeyondLastLine:false}}/>
        </div>}

        {/* Tool selector */}
        <div className="flex gap-1.5 flex-wrap">
          {([
            {id:"decode" as const,label:"فك التشفير",icon:Hash,color:"text-emerald-400 border-emerald-500/30"},
            {id:"xref" as const,label:"مراجع متقاطعة",icon:Link2,color:"text-cyan-400 border-cyan-500/30"},
            {id:"hierarchy" as const,label:"شجرة الوراثة",icon:Layers,color:"text-blue-400 border-blue-500/30"},
            {id:"dataflow" as const,label:"تدفق البيانات",icon:Network,color:"text-orange-400 border-orange-500/30"},
            {id:"methods" as const,label:"بحث التوقيعات",icon:Braces,color:"text-purple-400 border-purple-500/30"},
            {id:"diff" as const,label:"مقارنة APK",icon:Diff,color:"text-pink-400 border-pink-500/30"},
          ] as const).map(t=><button key={t.id} onClick={()=>setFPanel(t.id)} className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium border transition-all ${fPanel===t.id?`bg-card shadow ${t.color}`:"border-border text-muted-foreground hover:text-foreground hover:bg-muted/20"}`}><t.icon className="w-3.5 h-3.5"/>{t.label}</button>)}
        </div>

        {/* ── Decode Strings Panel ── */}
        {fPanel==="decode"&&<div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 flex-1"><Hash className="w-4 h-4 text-emerald-400"/><span className="text-sm font-semibold">كشف وفك النصوص المشفرة</span><span className="text-[10px] text-muted-foreground">Base64 · Hex · URL · Unicode</span></div>
            <Button onClick={doDecodeStrings} disabled={fDecodedLoading||!iSess} size="sm" className="gap-2">{fDecodedLoading?<Loader2 className="w-4 h-4 animate-spin"/>:<Search className="w-4 h-4"/>}فحص</Button>
          </div>
          {fDecoded.length>0&&<div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl divide-y divide-border/30">
            <div className="px-3 py-2 bg-muted/20 flex items-center gap-2 text-xs font-semibold sticky top-0 z-10"><span className="text-emerald-400">{fDecoded.length}</span> نص مكشوف</div>
            {fDecoded.map((d:any,i:number)=><div key={i} className="px-3 py-2 hover:bg-muted/10 space-y-1">
              <div className="flex items-center gap-2 text-xs"><span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${d.encoding==="base64"?"bg-emerald-500/20 text-emerald-300":d.encoding==="hex"?"bg-orange-500/20 text-orange-300":d.encoding==="url"?"bg-blue-500/20 text-blue-300":"bg-purple-500/20 text-purple-300"}`}>{d.encoding.toUpperCase()}</span><span className="text-muted-foreground font-mono truncate max-w-[200px]">{d.file}</span><span className="text-muted-foreground/50">:{d.line}</span><span className="mr-auto text-[10px] text-muted-foreground">{d.confidence}%</span></div>
              <div className="font-mono text-[11px] text-muted-foreground/60 truncate">{d.original}</div>
              <div className="font-mono text-[11px] text-emerald-300 truncate">→ {d.decoded}</div>
            </div>)}
          </div>}
        </div>}

        {/* ── Cross-Reference Panel ── */}
        {fPanel==="xref"&&<div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-2">
            <Link2 className="w-4 h-4 text-cyan-400"/>
            <span className="text-sm font-semibold">مراجع متقاطعة (Xref)</span>
          </div>
          <div className="flex gap-2"><input value={fXrefQuery} onChange={e=>setFXrefQuery(e.target.value)} onKeyDown={e=>e.key==="Enter"&&doXref()} placeholder="اسم كلاس أو ميثود مثل: MainActivity أو onClick" className="flex-1 bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm font-mono text-right" disabled={!iSess}/><Button onClick={doXref} disabled={!iSess||fXrefLoading||!fXrefQuery.trim()}>{fXrefLoading?<Loader2 className="w-4 h-4 animate-spin"/>:<Search className="w-4 h-4"/>}</Button></div>
          {fXref&&<div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl">
            <div className="px-3 py-2 bg-muted/20 flex items-center gap-2 text-xs font-semibold sticky top-0 z-10 border-b border-border"><span className="text-cyan-400">{fXref.totalCount}</span> مرجع لـ <span className="font-mono text-cyan-300">{fXref.target}</span></div>
            <div className="divide-y divide-border/30 max-h-96 overflow-y-auto">{(fXref.references||[]).map((r:any,i:number)=><div key={i} className="px-3 py-2 hover:bg-muted/10 space-y-0.5">
              <div className="flex items-center gap-2 text-xs"><span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${r.type==="invoke"?"bg-blue-500/20 text-blue-300":r.type==="field"?"bg-orange-500/20 text-orange-300":r.type==="type"?"bg-purple-500/20 text-purple-300":"bg-muted/30 text-muted-foreground"}`}>{r.type}</span><span className="font-mono text-muted-foreground truncate">{r.file}</span><span className="text-muted-foreground/50">:{r.line}</span></div>
              <div className="font-mono text-[11px] text-muted-foreground/80 truncate">{r.context}</div>
            </div>)}</div>
          </div>}
        </div>}

        {/* ── Class Hierarchy Panel ── */}
        {fPanel==="hierarchy"&&<div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 flex-1"><Layers className="w-4 h-4 text-blue-400"/><span className="text-sm font-semibold">شجرة الوراثة</span></div>
            <Button onClick={doHierarchy} disabled={fHierarchyLoading||!iSess} size="sm" className="gap-2">{fHierarchyLoading?<Loader2 className="w-4 h-4 animate-spin"/>:<Layers className="w-4 h-4"/>}تحليل</Button>
          </div>
          {fHierarchy&&<>
            <div className="grid grid-cols-4 gap-3">
              {([["كلاسات",fHierarchy.stats.totalClasses,"text-blue-400 bg-blue-500/10 border-blue-500/30"],["واجهات",fHierarchy.stats.interfaces,"text-purple-400 bg-purple-500/10 border-purple-500/30"],["مجردة",fHierarchy.stats.abstractClasses,"text-orange-400 bg-orange-500/10 border-orange-500/30"],["أقصى عمق",fHierarchy.stats.maxDepth,"text-emerald-400 bg-emerald-500/10 border-emerald-500/30"]] as const).map(([l,v,cls])=><div key={l} className={`p-3 rounded-xl border text-center ${cls}`}><div className="text-2xl font-bold">{v}</div><div className="text-xs">{l}</div></div>)}
            </div>
            <div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl">
              <div className="px-3 py-2 bg-muted/20 text-xs font-semibold sticky top-0 z-10 border-b border-border">أهم الكلاسات (بعدد الأبناء)</div>
              <div className="divide-y divide-border/30 max-h-96 overflow-y-auto">{(fHierarchy.classes||[]).filter((c:any)=>c.children.length>0).sort((a:any,b:any)=>b.children.length-a.children.length).slice(0,100).map((c:any,i:number)=><div key={i} className="px-3 py-2 hover:bg-muted/10">
                <div className="flex items-center gap-2 text-xs"><span className={`w-2 h-2 rounded-full ${c.isInterface?"bg-purple-400":c.isAbstract?"bg-orange-400":"bg-blue-400"}`}/><span className="font-mono text-foreground truncate">{c.name}</span><span className="mr-auto text-muted-foreground">{c.children.length} ابن · {c.methods} ميثود · {c.fields} حقل</span></div>
                <div className="text-[10px] text-muted-foreground/60 font-mono mt-0.5 truncate">↑ {c.superClass}</div>
              </div>)}</div>
            </div>
          </>}
        </div>}

        {/* ── Data Flow Panel ── */}
        {fPanel==="dataflow"&&<div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 flex-1"><Network className="w-4 h-4 text-orange-400"/><span className="text-sm font-semibold">تحليل تدفق البيانات</span><span className="text-[10px] text-muted-foreground">تتبع APIs الحساسة · Sources · Sinks</span></div>
            <Button onClick={doDataFlow} disabled={fDataFlowLoading||!iSess} size="sm" className="gap-2">{fDataFlowLoading?<Loader2 className="w-4 h-4 animate-spin"/>:<Network className="w-4 h-4"/>}تحليل</Button>
          </div>
          {fDataFlow&&<>
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 rounded-xl border text-center bg-red-500/10 border-red-500/30 text-red-400"><div className="text-2xl font-bold">{fDataFlow.sensitiveApis?.length||0}</div><div className="text-xs">APIs حساسة</div></div>
              <div className="p-3 rounded-xl border text-center bg-orange-500/10 border-orange-500/30 text-orange-400"><div className="text-2xl font-bold">{fDataFlow.sinks?.length||0}</div><div className="text-xs">Sinks</div></div>
              <div className="p-3 rounded-xl border text-center bg-blue-500/10 border-blue-500/30 text-blue-400"><div className="text-2xl font-bold">{fDataFlow.sources?.length||0}</div><div className="text-xs">Sources</div></div>
            </div>
            {fDataFlow.sensitiveApis?.length>0&&<div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl">
              <div className="px-3 py-2 bg-muted/20 text-xs font-semibold sticky top-0 z-10 border-b border-border">APIs حساسة مكتشفة</div>
              <div className="divide-y divide-border/30 max-h-96 overflow-y-auto">{fDataFlow.sensitiveApis.map((a:any,i:number)=><div key={i} className="px-3 py-2 hover:bg-muted/10 space-y-1">
                <div className="flex items-center gap-2 text-xs"><span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${a.category==="crypto"?"bg-yellow-500/20 text-yellow-300":a.category==="network"?"bg-blue-500/20 text-blue-300":a.category==="sms"?"bg-red-500/20 text-red-300":a.category==="location"?"bg-green-500/20 text-green-300":"bg-muted/30 text-muted-foreground"}`}>{a.category}</span><span className="font-semibold text-foreground">{a.api}</span><span className="mr-auto font-mono text-muted-foreground truncate max-w-[200px]">{a.file}:{a.line}</span></div>
                <div className="font-mono text-[11px] text-muted-foreground/70 truncate">{a.context}</div>
                {a.dataFlow?.length>0&&<div className="bg-black/20 rounded p-1.5 space-y-0.5">{a.dataFlow.map((l:string,j:number)=><div key={j} className="font-mono text-[10px] text-muted-foreground/60 truncate">{l}</div>)}</div>}
              </div>)}</div>
            </div>}
          </>}
        </div>}

        {/* ── Method Signature Search Panel ── */}
        {fPanel==="methods"&&<div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-2"><Braces className="w-4 h-4 text-purple-400"/><span className="text-sm font-semibold">بحث التوقيعات</span></div>
          <div className="flex gap-2"><input value={fMethodQuery} onChange={e=>setFMethodQuery(e.target.value)} onKeyDown={e=>e.key==="Enter"&&doMethodSearch()} placeholder="اسم ميثود مثل: onCreate, checkLicense, isPremium" className="flex-1 bg-muted/30 border border-border rounded-lg px-3 py-2 text-sm font-mono text-right" disabled={!iSess}/><Button onClick={doMethodSearch} disabled={!iSess||fMethodLoading||!fMethodQuery.trim()}>{fMethodLoading?<Loader2 className="w-4 h-4 animate-spin"/>:<Search className="w-4 h-4"/>}</Button></div>
          <div className="flex gap-1.5 flex-wrap">{["onCreate","onClick","isPremium","checkLicense","decrypt","verify","init","onReceive","sendSMS","getDeviceId"].map(q=><button key={q} onClick={()=>{setFMethodQuery(q);}} className="text-[10px] px-2 py-1 rounded-full bg-muted/30 border border-border text-muted-foreground hover:text-foreground hover:bg-purple-500/10 hover:border-purple-500/30 transition-all">{q}</button>)}</div>
          {fMethodSearch&&<div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl">
            <div className="px-3 py-2 bg-muted/20 text-xs font-semibold sticky top-0 z-10 border-b border-border"><span className="text-purple-400">{fMethodSearch.totalFound}</span> ميثود</div>
            <div className="divide-y divide-border/30 max-h-96 overflow-y-auto">{(fMethodSearch.methods||[]).map((m:any,i:number)=><div key={i} className="px-3 py-2 hover:bg-muted/10 space-y-0.5">
              <div className="flex items-center gap-2 text-xs"><span className="text-purple-300 font-semibold">{m.methodName}</span><span className="font-mono text-muted-foreground/60 truncate">{m.signature}</span></div>
              <div className="flex items-center gap-2 text-[10px] text-muted-foreground"><span className="font-mono truncate max-w-[250px]">{m.file}:{m.line}</span><span>·</span><span>{m.linesOfCode} سطر</span><span>·</span><span>{m.registers} مسجل</span><span className="mr-auto text-muted-foreground/50">{m.modifiers}</span></div>
            </div>)}</div>
          </div>}
        </div>}

        {/* ── APK Diff Panel ── */}
        {fPanel==="diff"&&<div className="flex-1 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-2"><Diff className="w-4 h-4 text-pink-400"/><span className="text-sm font-semibold">مقارنة ملفين</span><span className="text-[10px] text-muted-foreground">ارفع نسختين لمقارنة الفروقات</span></div>
          <div className="grid grid-cols-2 gap-3">
            <div className="border border-dashed border-border rounded-xl p-4 text-center cursor-pointer hover:border-pink-500/40 hover:bg-pink-500/5 transition-all" onClick={()=>fDiffRef1.current?.click()}>
              <input ref={fDiffRef1} type="file" accept={ACCEPT_STR} className="hidden" onChange={e=>{if(e.target.files?.[0])setFDiffFile1(e.target.files[0]);}}/>
              <Upload className="w-6 h-6 mx-auto mb-1 text-muted-foreground"/>
              <div className="text-xs font-semibold">{fDiffFile1?fDiffFile1.name:"النسخة القديمة"}</div>
              {fDiffFile1&&<div className="text-[10px] text-muted-foreground mt-1">{fmtB(fDiffFile1.size)}</div>}
            </div>
            <div className="border border-dashed border-border rounded-xl p-4 text-center cursor-pointer hover:border-pink-500/40 hover:bg-pink-500/5 transition-all" onClick={()=>fDiffRef2.current?.click()}>
              <input ref={fDiffRef2} type="file" accept={ACCEPT_STR} className="hidden" onChange={e=>{if(e.target.files?.[0])setFDiffFile2(e.target.files[0]);}}/>
              <Upload className="w-6 h-6 mx-auto mb-1 text-muted-foreground"/>
              <div className="text-xs font-semibold">{fDiffFile2?fDiffFile2.name:"النسخة الجديدة"}</div>
              {fDiffFile2&&<div className="text-[10px] text-muted-foreground mt-1">{fmtB(fDiffFile2.size)}</div>}
            </div>
          </div>
          <Button onClick={doDiff} disabled={fDiffLoading||!fDiffFile1||!fDiffFile2} className="gap-2 self-start">{fDiffLoading?<Loader2 className="w-4 h-4 animate-spin"/>:<Diff className="w-4 h-4"/>}مقارنة</Button>
          {fDiff&&<>
            <div className="grid grid-cols-4 gap-3">
              <div className="p-3 rounded-xl border text-center bg-emerald-500/10 border-emerald-500/30 text-emerald-400"><div className="text-2xl font-bold">{fDiff.summary?.totalAdded||0}</div><div className="text-xs">مضافة</div></div>
              <div className="p-3 rounded-xl border text-center bg-red-500/10 border-red-500/30 text-red-400"><div className="text-2xl font-bold">{fDiff.summary?.totalRemoved||0}</div><div className="text-xs">محذوفة</div></div>
              <div className="p-3 rounded-xl border text-center bg-yellow-500/10 border-yellow-500/30 text-yellow-400"><div className="text-2xl font-bold">{fDiff.summary?.totalModified||0}</div><div className="text-xs">معدّلة</div></div>
              <div className="p-3 rounded-xl border text-center bg-muted/20 border-border text-muted-foreground"><div className="text-2xl font-bold">{fDiff.summary?.totalUnchanged||0}</div><div className="text-xs">بدون تغيير</div></div>
            </div>
            {fDiff.summary?.versionChange&&<div className="text-xs text-muted-foreground bg-muted/20 rounded-lg px-3 py-2">الإصدار: <span className="text-red-400">{fDiff.summary.versionChange.old}</span> → <span className="text-emerald-400">{fDiff.summary.versionChange.new}</span></div>}
            {(fDiff.summary?.permissionChanges?.added?.length>0||fDiff.summary?.permissionChanges?.removed?.length>0)&&<div className="bg-card/70 border border-border rounded-xl p-3 space-y-1">
              <div className="text-xs font-semibold">تغييرات الأذونات</div>
              {fDiff.summary.permissionChanges.added?.map((p:string,i:number)=><div key={"a"+i} className="text-[11px] font-mono text-emerald-400">+ {p}</div>)}
              {fDiff.summary.permissionChanges.removed?.map((p:string,i:number)=><div key={"r"+i} className="text-[11px] font-mono text-red-400">- {p}</div>)}
            </div>}
            <div className="flex-1 overflow-y-auto bg-card/70 backdrop-blur-sm border border-border rounded-xl">
              <div className="divide-y divide-border/30 max-h-64 overflow-y-auto">
                {fDiff.added?.slice(0,50).map((f:string,i:number)=><div key={"a"+i} className="px-3 py-1.5 text-xs font-mono text-emerald-400 hover:bg-muted/10">+ {f}</div>)}
                {fDiff.removed?.slice(0,50).map((f:string,i:number)=><div key={"r"+i} className="px-3 py-1.5 text-xs font-mono text-red-400 hover:bg-muted/10">- {f}</div>)}
                {fDiff.modified?.slice(0,50).map((f:any,i:number)=><div key={"m"+i} className="px-3 py-1.5 text-xs font-mono text-yellow-400 hover:bg-muted/10 flex items-center gap-2">~ {f.path} <span className="mr-auto text-muted-foreground">{f.sizeDiff>0?"+":""}{fmtB(Math.abs(f.sizeDiff))}</span></div>)}
              </div>
            </div>
          </>}
        </div>}

        </div>
      </div>}

      {/* ══ TAB 6: CLOUD PENTEST ══ */}
      {tab==="cloudpen"&&<div className="flex-1 flex flex-col gap-4 min-h-0 overflow-y-auto">

        {/* ── PHASE 1: Upload & Start ── */}
        {!cpResult&&!cpLoading&&<div className="flex-1 flex flex-col items-center justify-center gap-6 py-8">
          <div className="text-center space-y-2">
            <div className="w-20 h-20 mx-auto rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 flex items-center justify-center">
              <Shield className="w-10 h-10 text-cyan-400"/>
            </div>
            <h2 className="text-2xl font-bold bg-gradient-to-r from-cyan-300 to-blue-400 bg-clip-text text-transparent">اختبار اختراق سحابي تلقائي</h2>
            <p className="text-sm text-muted-foreground max-w-lg mx-auto">ارفع ملف APK واضغط "ابدأ الاختبار" — سيتم تنفيذ 8 خطوات تلقائياً: تفكيك، مصادقة، مفاتيح، استغلال IDOR، تعديل Pro، سحب بيانات، إرسال Telegram، وسكريبت + تقرير</p>
          </div>
          <input type="file" ref={cpFileRef} accept=".apk" className="hidden" onChange={e=>{if(e.target.files?.[0])setCpFile(e.target.files[0]);}}/>
          <div className={`w-full max-w-xl border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all ${cpFile?"border-cyan-500/60 bg-cyan-500/5":"border-border/50 hover:border-cyan-500/40 hover:bg-cyan-500/5"}`} onClick={()=>cpFileRef.current?.click()}>
            {cpFile?<div className="space-y-2">
              <Package className="w-10 h-10 text-cyan-400 mx-auto"/>
              <div className="text-lg font-semibold text-cyan-300">{cpFile.name}</div>
              <div className="text-xs text-muted-foreground">{(cpFile.size/1024/1024).toFixed(1)} MB</div>
              <div className="text-[11px] text-cyan-400/70">اضغط لتغيير الملف</div>
            </div>:<div className="space-y-2">
              <Upload className="w-10 h-10 text-muted-foreground mx-auto"/>
              <div className="text-sm text-muted-foreground">اسحب ملف APK هنا أو اضغط للاختيار</div>
            </div>}
          </div>
          <Button onClick={doCloudPentestFull} disabled={!cpFile} size="lg" className="gap-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-base px-8 py-6 rounded-xl shadow-lg shadow-cyan-900/30">
            <Zap className="w-5 h-5"/>ابدأ الاختبار التلقائي
          </Button>
          <div className="grid grid-cols-8 gap-1.5 w-full max-w-xl">
            {["تفكيك","مصادقة","مفاتيح","IDOR","استغلال","سحب DB","Telegram","تقرير"].map((s,i)=><div key={i} className="text-center">
              <div className="w-7 h-7 mx-auto rounded-full bg-muted/20 border border-border/50 flex items-center justify-center text-[10px] font-bold text-muted-foreground">{i+1}</div>
              <div className="text-[8px] text-muted-foreground mt-1">{s}</div>
            </div>)}
          </div>
        </div>}

        {/* ── PHASE 2: Live Execution (Steps Revealing) ── */}
        {cpLoading&&<div className="space-y-4">
          <div className="bg-gradient-to-r from-cyan-900/40 to-blue-900/40 border border-cyan-500/30 rounded-2xl p-5">
            <div className="flex items-center gap-3">
              <Loader2 className="w-6 h-6 animate-spin text-cyan-400"/>
              <div>
                <h2 className="text-lg font-bold text-cyan-300">جاري تنفيذ اختبار الاختراق...</h2>
                <p className="text-xs text-muted-foreground">الملف: {cpFile?.name} ({cpFile?((cpFile.size/1024/1024).toFixed(1)+" MB"):""})</p>
              </div>
            </div>
            <div className="mt-4 h-2 bg-muted/20 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-1000" style={{width:`${(cpActiveStep/8)*100}%`}}/>
            </div>
            <div className="text-[11px] text-muted-foreground mt-2 text-left">{cpActiveStep}/8 خطوات</div>
          </div>
          {[
            {id:1,title:"تفكيك APK وتحليل الهيكل الداخلي",desc:"apktool + jadx + Manifest + google-services.json + smali",icon:"📦"},
            {id:2,title:"استخراج التوكن الحقيقي (JWT/Bearer)",desc:"SharedPreferences + Frida + ADB + smali const-string",icon:"🔐"},
            {id:3,title:"استخراج المفاتيح والتوكنات من الكود",desc:"Firebase keys, AWS, JWT, Bearer tokens, API keys",icon:"🔑"},
            {id:4,title:"استغلال API وجلب بيانات المستخدمين (IDOR)",desc:"/api/users + /api/user/ID + IDOR enumeration",icon:"🌐"},
            {id:5,title:"استغلال الحسابات — ترقية/تخفيض/تحويل/PIN",desc:"ترقية + تخفيض خطة + تحويل رصيد + إعادة تعيين PIN",icon:"💎"},
            {id:6,title:"سحب قاعدة البيانات السحابية بالكامل",desc:"Firebase RTDB dump + REST API pagination + S3/MongoDB",icon:"📡"},
            {id:7,title:"إرسال البيانات المسروقة إلى بوت Telegram",desc:"sendMessage + sendDocument + تقسيم 4096 حرف",icon:"🤖"},
            {id:8,title:"السكريبت المتكامل + التقرير النهائي",desc:"Python script + تقرير احترافي + توصيات الإصلاح",icon:"⚙️"},
          ].map(step=>{
            const revealed=cpStepsRevealed.includes(step.id);
            const active=cpActiveStep===step.id;
            return(<div key={step.id} className={`rounded-xl border overflow-hidden transition-all duration-700 ${!revealed?"opacity-20 border-border/20":"opacity-100"} ${active?"border-cyan-500/60 bg-cyan-500/5 shadow-lg shadow-cyan-900/20":"border-border/40 bg-card/30"}`}>
              <div className="flex items-center gap-3 p-4">
                <span className={`w-10 h-10 rounded-full flex items-center justify-center text-lg shrink-0 ${active?"bg-cyan-500/20 animate-pulse":"bg-muted/20"}`}>{active?<Loader2 className="w-5 h-5 animate-spin text-cyan-400"/>:revealed?"✅":step.icon}</span>
                <div className="flex-1 text-right">
                  <div className={`font-semibold text-sm ${active?"text-cyan-300":"text-foreground/80"}`}>{step.title}</div>
                  <div className="text-[11px] text-muted-foreground">{step.desc}</div>
                </div>
                <span className={`text-[10px] px-2 py-0.5 rounded-full ${active?"bg-cyan-500/20 text-cyan-300 border border-cyan-500/40":"bg-muted/10 text-muted-foreground border border-transparent"}`}>{active?"جاري...":revealed?"مكتمل":"في الانتظار"}</span>
              </div>
            </div>);
          })}
        </div>}

        {/* ── PHASE 3: Results ── */}
        {cpResult&&<>
          {/* Header with file info */}
          <div className="bg-gradient-to-r from-cyan-900/40 to-blue-900/40 border border-cyan-500/30 rounded-2xl p-5">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div>
                <h2 className="text-xl font-bold flex items-center gap-2"><Shield className="w-6 h-6 text-cyan-400"/>تقرير اختبار الاختراق السحابي</h2>
                <p className="text-xs text-muted-foreground mt-1">الملف: <span className="text-cyan-300 font-mono">{cpResult.fileName||cpFile?.name}</span> · {cpResult.fileSize?((cpResult.fileSize/1024/1024).toFixed(1)+" MB"):""} · {new Date(cpResult.generatedAt).toLocaleString("ar-EG")}</p>
              </div>
              <div className="flex items-center gap-2">
                <Button onClick={()=>{setCpResult(null);setCpFile(null);setCpStepsRevealed([]);setCpActiveStep(0);}} variant="outline" className="gap-2 border-cyan-500/30 text-cyan-300"><Undo2 className="w-4 h-4"/>اختبار جديد</Button>
                <Button onClick={()=>{const blob=new Blob([JSON.stringify(cpResult,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`cloud-pentest-${Date.now()}.json`;a.click();URL.revokeObjectURL(url);}} variant="outline" className="gap-2 border-cyan-500/30 text-cyan-300"><Download className="w-4 h-4"/>تصدير JSON</Button>
              </div>
            </div>
          </div>

          {/* Risk Score Dashboard */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className={`p-4 rounded-xl border text-center ${cpResult.summary.riskScore>60?"bg-red-500/10 border-red-500/40 shadow-lg shadow-red-900/20":"bg-cyan-500/10 border-cyan-500/30"}`}>
              <div className={`text-4xl font-black ${cpResult.summary.riskScore>60?"text-red-400":cpResult.summary.riskScore>30?"text-yellow-400":"text-emerald-400"}`}>{cpResult.summary.riskScore}</div>
              <div className="text-[10px] text-muted-foreground mt-1">درجة الخطورة /100</div>
              <div className={`text-[11px] mt-1 font-semibold ${cpResult.summary.riskScore>60?"text-red-400":"text-emerald-400"}`}>{cpResult.summary.riskScore>60?"خطر مرتفع":cpResult.summary.riskScore>30?"خطر متوسط":"آمن نسبياً"}</div>
            </div>
            <div className="p-4 rounded-xl border bg-red-500/10 border-red-500/30 text-center">
              <div className="text-3xl font-bold text-red-400">{cpResult.summary.criticalCount}</div>
              <div className="text-[10px] text-muted-foreground mt-1">ثغرات حرجة</div>
            </div>
            <div className="p-4 rounded-xl border bg-orange-500/10 border-orange-500/30 text-center">
              <div className="text-3xl font-bold text-orange-400">{cpResult.summary.highCount}</div>
              <div className="text-[10px] text-muted-foreground mt-1">تحذيرات</div>
            </div>
            <div className="p-4 rounded-xl border bg-blue-500/10 border-blue-500/30 text-center">
              <div className="text-3xl font-bold text-blue-400">{cpResult.summary.extractedKeys?.length||0}</div>
              <div className="text-[10px] text-muted-foreground mt-1">مفاتيح مستخرجة</div>
            </div>
            <div className="p-4 rounded-xl border bg-violet-500/10 border-violet-500/30 text-center">
              <div className="text-3xl font-bold text-violet-400">{cpResult.summary.extractedEndpoints?.length||0}</div>
              <div className="text-[10px] text-muted-foreground mt-1">نقاط دخول API</div>
            </div>
          </div>

          {/* Cloud Providers */}
          {cpResult.summary?.cloudProviders?.length>0&&<div className="flex items-center gap-2 flex-wrap bg-card/50 border border-border/50 rounded-xl px-4 py-3">
            <span className="text-xs text-muted-foreground font-semibold">تقنيات مكتشفة:</span>
            {cpResult.summary.cloudProviders.map((p:string,i:number)=><span key={i} className="text-[11px] px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-medium">{p}</span>)}
          </div>}

          {/* 7 Steps with full details */}
          <div className="space-y-3">
            <div className="text-sm font-semibold text-cyan-300 flex items-center gap-2"><Terminal className="w-4 h-4"/>الخطوات التنفيذية (8 خطوات)</div>
            {cpResult.steps.map((step:any)=>{
              const isOpen=cpExpanded.has(step.id);
              const statusColors:Record<string,string>={critical:"border-red-500/40 bg-red-500/5",warning:"border-orange-500/30 bg-orange-500/5",info:"border-blue-500/20 bg-blue-500/5",success:"border-emerald-500/30 bg-emerald-500/5"};
              const statusIcons:Record<string,string>={critical:"🔴",warning:"🟡",info:"🔵",success:"🟢"};
              const statusLabels:Record<string,string>={critical:"حرج",warning:"تحذير",info:"معلومة",success:"آمن"};
              return(<div key={step.id} className={`rounded-xl border overflow-hidden transition-all ${statusColors[step.status]||"border-border"}`}>
                <button onClick={()=>{const n=new Set(cpExpanded);if(n.has(step.id))n.delete(step.id);else n.add(step.id);setCpExpanded(n);}} className="w-full flex items-center gap-3 p-4 hover:bg-white/5 transition-all text-right">
                  <span className="w-10 h-10 rounded-full bg-muted/30 flex items-center justify-center text-sm font-bold text-cyan-400 shrink-0">{step.id}</span>
                  <div className="flex-1 text-right">
                    <div className="font-semibold text-sm">{step.title}</div>
                    <div className="text-[11px] text-muted-foreground mt-0.5">{step.details}</div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[11px] px-2 py-1 rounded-full border bg-muted/20 font-medium">{statusIcons[step.status]} {statusLabels[step.status]}</span>
                    <span className="text-[10px] text-muted-foreground bg-muted/10 px-2 py-0.5 rounded-full">{step.findings?.length||0} نتائج</span>
                    {isOpen?<ChevronDown className="w-4 h-4 text-muted-foreground"/>:<ChevronRight className="w-4 h-4 text-muted-foreground"/>}
                  </div>
                </button>
                {isOpen&&<div className="border-t border-border/30 p-4 space-y-3 bg-black/20">
                  {step.findings?.length>0&&<div className="space-y-1">
                    <div className="text-[11px] font-semibold text-cyan-300 flex items-center gap-1"><Search className="w-3 h-3"/>الاكتشافات ({step.findings.length})</div>
                    <div className="bg-black/30 rounded-lg p-3 max-h-[400px] overflow-y-auto space-y-0.5">
                      {step.findings.map((f:string,i:number)=><div key={i} className={`text-xs font-mono leading-relaxed ${f.includes("CRITICAL")?"text-red-400 font-bold":f.includes("✅")&&(f.includes("[200]")||f.includes("IDOR")||f.includes("نجح"))?"text-emerald-400 font-semibold":f.includes("✅")?"text-emerald-300":f.includes("⚠️")?"text-orange-400":f.includes("🔑")?"text-yellow-300":f.includes("🔥")||f.includes("🚨")?"text-red-300 font-semibold":f.includes("═══")?"text-cyan-300 font-bold border-b border-cyan-800/30 pb-1 mb-1":f.includes("📊")?"text-blue-300 font-semibold":f.includes("👤")?"text-pink-300":f.includes("💸")||f.includes("💳")||f.includes("📤")||f.includes("📥")?"text-amber-300":f.includes("❌")?"text-red-400":f.includes("→")?"text-cyan-300/80":"text-muted-foreground"}`}>{f}</div>)}
                    </div>
                  </div>}
                  {step.commands?.length>0&&<div className="space-y-1">
                    <div className="text-[11px] font-semibold text-emerald-300 flex items-center gap-1"><Terminal className="w-3 h-3"/>أوامر التنفيذ ({step.commands.length})</div>
                    <div className="bg-black/40 rounded-lg p-3 max-h-48 overflow-y-auto space-y-2">
                      {step.commands.map((cmd:string,i:number)=><div key={i} className="flex items-start gap-2 group bg-black/30 rounded-lg px-3 py-2">
                        <span className="text-emerald-500 text-xs mt-0.5 shrink-0">$</span>
                        <code className="text-[11px] font-mono text-emerald-300 flex-1 break-all">{cmd}</code>
                        <button onClick={()=>{navigator.clipboard.writeText(cmd);toast.success("تم نسخ الأمر");}} className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0 bg-emerald-500/10 hover:bg-emerald-500/20 rounded p-1"><Copy className="w-3 h-3 text-emerald-400"/></button>
                      </div>)}
                    </div>
                  </div>}
                  {step.pythonScript&&<div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="text-[11px] font-semibold text-amber-300 flex items-center gap-1"><Code className="w-3 h-3"/>السكريبت المتكامل (Python)</div>
                      <button onClick={()=>{navigator.clipboard.writeText(step.pythonScript);toast.success("تم نسخ السكريبت الكامل");}} className="text-[10px] px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300 hover:bg-amber-500/20 flex items-center gap-1"><Copy className="w-3 h-3"/>نسخ السكريبت الكامل</button>
                    </div>
                    <div className="bg-black/50 rounded-lg p-3 max-h-80 overflow-y-auto border border-amber-500/20">
                      <pre className="text-[10px] font-mono text-amber-200/80 whitespace-pre-wrap leading-relaxed">{step.pythonScript}</pre>
                    </div>
                    <div className="flex gap-2">
                      <button onClick={()=>{const blob=new Blob([step.pythonScript],{type:"text/x-python"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="pentest_auto.py";a.click();URL.revokeObjectURL(url);}} className="text-[10px] px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300 hover:bg-amber-500/20 flex items-center gap-1"><Download className="w-3 h-3"/>تحميل pentest_auto.py</button>
                    </div>
                  </div>}
                </div>}
              </div>);
            })}
          </div>

          {/* Extracted Endpoints */}
          {cpResult.summary?.extractedEndpoints?.length>0&&<div className="bg-card/70 border border-border rounded-xl p-4 space-y-2">
            <div className="text-sm font-semibold flex items-center gap-2"><Globe className="w-4 h-4 text-violet-400"/>نقاط الدخول المكتشفة ({cpResult.summary.extractedEndpoints.length})</div>
            <div className="max-h-48 overflow-y-auto space-y-1">
              {cpResult.summary.extractedEndpoints.slice(0,30).map((url:string,i:number)=><div key={i} className="flex items-center gap-2 group bg-black/20 rounded-lg px-3 py-1.5">
                <Globe className="w-3 h-3 text-violet-400 shrink-0"/>
                <code className="text-[11px] font-mono text-violet-300 break-all flex-1">{url}</code>
                <button onClick={()=>{navigator.clipboard.writeText(url);toast.success("تم النسخ");}} className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0"><Copy className="w-3 h-3 text-muted-foreground hover:text-white"/></button>
              </div>)}
            </div>
          </div>}

          {/* AI Report */}
          {cpResult.report&&<div className="space-y-2">
            <button onClick={()=>setCpShowReport(r=>!r)} className="w-full flex items-center gap-2 text-sm font-semibold text-cyan-300 hover:text-cyan-200 transition-colors bg-card/50 border border-cyan-500/20 rounded-xl px-4 py-3">
              <BookOpen className="w-5 h-5"/><span className="flex-1 text-right">التقرير الاحترافي بالذكاء الاصطناعي</span>
              {cpShowReport?<ChevronDown className="w-4 h-4"/>:<ChevronRight className="w-4 h-4"/>}
            </button>
            {cpShowReport&&<div className="bg-card/70 backdrop-blur-sm border border-cyan-500/20 rounded-xl p-6 max-h-[500px] overflow-y-auto">
              <div className="prose prose-invert prose-sm max-w-none text-sm leading-relaxed whitespace-pre-wrap">{cpResult.report}</div>
              <div className="flex gap-2 mt-4 pt-3 border-t border-border/30">
                <Button onClick={()=>{navigator.clipboard.writeText(cpResult.report);toast.success("تم نسخ التقرير");}} variant="outline" className="gap-2 text-xs"><Copy className="w-3 h-3"/>نسخ التقرير</Button>
                <Button onClick={()=>{const blob=new Blob([cpResult.report],{type:"text/markdown"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`pentest-report-${Date.now()}.md`;a.click();URL.revokeObjectURL(url);}} variant="outline" className="gap-2 text-xs"><Download className="w-3 h-3"/>تحميل التقرير</Button>
              </div>
            </div>}
          </div>}

          <div className="text-center text-[10px] text-muted-foreground border-t border-border/30 pt-3 mt-2">
            ⚠️ الاستخدام الأكاديمي فقط — اختبار الاختراق الأخلاقي ضمن بيئة مرخصة وبموافقة مسبقة
          </div>
        </>}
      </div>}

    </div>
  </DashboardLayout>);
}
