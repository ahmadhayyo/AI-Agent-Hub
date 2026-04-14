import { useState, useCallback, useEffect } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { toast } from "sonner";
import {
  Shield, Home, Loader2, Search, Globe, Mail, User, Phone, Server,
  Lock, Network, MapPin, ExternalLink, Copy, Check,
  Eye, Code2, X, Database, BarChart3, ChevronDown,
  Signal, Fingerprint, Radio, Wifi, AlertTriangle,
  Upload, CloudDownload, HardDrive, Trash2, FileSpreadsheet, RefreshCw, FolderOpen,
} from "lucide-react";

type Tab = "tools" | "callerid" | "coverage" | "import";
type Tool = "ip" | "whois" | "dns" | "email" | "username" | "phone" | "tech" | "ssl" | "subdomain";

const TOOLS: Array<{ id: Tool; icon: any; label: string; desc: string; placeholder: string; color: string }> = [
  { id: "ip", icon: MapPin, label: "تحديد موقع IP", desc: "الدولة، المدينة، ISP، الإحداثيات", placeholder: "8.8.8.8", color: "from-red-500 to-orange-500" },
  { id: "whois", icon: Globe, label: "WHOIS Lookup", desc: "مالك الدومين، تاريخ التسجيل", placeholder: "example.com", color: "from-blue-500 to-cyan-500" },
  { id: "dns", icon: Server, label: "DNS Records", desc: "سجلات A, MX, TXT, NS, CNAME", placeholder: "example.com", color: "from-emerald-500 to-teal-500" },
  { id: "email", icon: Mail, label: "فحص تسريب الإيميل", desc: "هل ظهر في تسريبات بيانات؟", placeholder: "user@example.com", color: "from-violet-500 to-purple-500" },
  { id: "username", icon: User, label: "بحث اسم المستخدم", desc: "20+ موقع: GitHub, Telegram, X...", placeholder: "ahmed_dev", color: "from-pink-500 to-rose-500" },
  { id: "phone", icon: Phone, label: "فحص رقم (خارجي)", desc: "Numverify + Truecaller Links", placeholder: "+905551234567", color: "from-amber-500 to-yellow-500" },
  { id: "tech", icon: Code2, label: "تقنيات الموقع", desc: "Framework, Server, CMS, Analytics", placeholder: "google.com", color: "from-indigo-500 to-blue-500" },
  { id: "ssl", icon: Lock, label: "شهادات SSL", desc: "سجل الشهادات والتواريخ", placeholder: "github.com", color: "from-emerald-500 to-green-500" },
  { id: "subdomain", icon: Network, label: "Subdomain Finder", desc: "اكتشاف النطاقات الفرعية", placeholder: "microsoft.com", color: "from-orange-500 to-red-500" },
];

function CopyBtn({ text }: { text: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setOk(true); toast.success("تم النسخ"); setTimeout(() => setOk(false), 2000); }}
      className="p-1 rounded hover:bg-secondary/50 text-muted-foreground"><Check className={`w-3 h-3 ${ok ? "text-emerald-400" : "hidden"}`} /><Copy className={`w-3 h-3 ${ok ? "hidden" : ""}`} /></button>
  );
}

function ResultCard({ title, icon, children, accent }: { title: string; icon?: React.ReactNode; children: React.ReactNode; accent?: string }) {
  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <div className={`px-4 py-2.5 border-b border-border ${accent || "bg-secondary/30"} flex items-center gap-2`}>
        {icon || <Eye className="w-4 h-4 text-primary" />}
        <span className="text-sm font-bold">{title}</span>
      </div>
      <div className="p-4 text-sm space-y-2">{children}</div>
    </div>
  );
}

function DataRow({ label, value, copyable }: { label: string; value: any; copyable?: boolean }) {
  if (value === null || value === undefined || value === "") return null;
  const str = typeof value === "object" ? JSON.stringify(value) : String(value);
  return (
    <div className="flex items-start justify-between gap-2 py-1.5 border-b border-border/30 last:border-0">
      <span className="text-xs text-muted-foreground shrink-0">{label}</span>
      <div className="flex items-center gap-1">
        <span className="text-xs text-foreground text-left font-mono break-all">{str}</span>
        {copyable && <CopyBtn text={str} />}
      </div>
    </div>
  );
}

function formatNum(n: number): string {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(1) + "B";
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(0) + "K";
  return String(n);
}

function CoverageTab() {
  const { data, isLoading, error } = trpc.osint.coverageStats.useQuery();

  if (isLoading) return <div className="flex items-center justify-center py-20"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
  if (error) return <div className="text-center py-10 text-red-400">فشل تحميل التغطية: {error.message}</div>;
  if (!data) return null;

  const regionOrder = ["GCC", "Arab", "Asia", "Europe", "North America", "South America", "Africa", "Oceania"];
  const regionColors: Record<string, string> = {
    GCC: "from-amber-500 to-orange-500",
    Arab: "from-emerald-500 to-teal-500",
    Asia: "from-blue-500 to-cyan-500",
    Europe: "from-violet-500 to-purple-500",
    "North America": "from-red-500 to-pink-500",
    "South America": "from-lime-500 to-green-500",
    Africa: "from-yellow-500 to-amber-500",
    Oceania: "from-sky-500 to-blue-500",
  };

  const coverageColors: Record<string, string> = {
    premium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    standard: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    basic: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-gradient-to-br from-amber-500/10 to-orange-500/10 border border-amber-500/20 rounded-xl p-4 text-center">
          <Globe className="w-6 h-6 text-amber-400 mx-auto mb-1" />
          <p className="text-2xl font-black text-amber-400">{data.totalCountries}</p>
          <p className="text-[10px] text-muted-foreground">دولة مغطاة</p>
        </div>
        <div className="bg-gradient-to-br from-emerald-500/10 to-teal-500/10 border border-emerald-500/20 rounded-xl p-4 text-center">
          <Database className="w-6 h-6 text-emerald-400 mx-auto mb-1" />
          <p className="text-2xl font-black text-emerald-400">{formatNum(data.totalRecords)}</p>
          <p className="text-[10px] text-muted-foreground">سجل في القاعدة</p>
        </div>
        <div className="bg-gradient-to-br from-violet-500/10 to-purple-500/10 border border-violet-500/20 rounded-xl p-4 text-center">
          <Fingerprint className="w-6 h-6 text-violet-400 mx-auto mb-1" />
          <p className="text-2xl font-black text-violet-400">{data.localContacts}</p>
          <p className="text-[10px] text-muted-foreground">جهة اتصال محلية</p>
        </div>
        <div className="bg-gradient-to-br from-red-500/10 to-pink-500/10 border border-red-500/20 rounded-xl p-4 text-center">
          <Radio className="w-6 h-6 text-red-400 mx-auto mb-1" />
          <p className="text-2xl font-black text-red-400">{Object.keys(data.sources).length}</p>
          <p className="text-[10px] text-muted-foreground">مصدر بيانات</p>
        </div>
      </div>

      <ResultCard title="مصادر البيانات — Data Sources" icon={<Signal className="w-4 h-4 text-amber-400" />} accent="bg-amber-500/5">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {Object.entries(data.sources).map(([key, src]: [string, any]) => (
            <div key={key} className="flex items-start gap-3 p-3 rounded-lg border border-border/40 bg-secondary/20">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-amber-500 to-orange-500 flex items-center justify-center shrink-0">
                <Database className="w-4 h-4 text-white" />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-bold">{src.name}</p>
                {src.version && <p className="text-[10px] text-muted-foreground">Version: {src.version}</p>}
                {src.identifier && <p className="text-[10px] text-muted-foreground">ID: {src.identifier}</p>}
                {src.records && <p className="text-[10px] text-emerald-400 font-bold">{src.records} records</p>}
                {src.source && <p className="text-[10px] text-muted-foreground">Source: {src.source}</p>}
              </div>
            </div>
          ))}
        </div>
      </ResultCard>

      <ResultCard title="تغطية المناطق — Regional Coverage" icon={<BarChart3 className="w-4 h-4 text-blue-400" />} accent="bg-blue-500/5">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {regionOrder.filter(r => data.regions[r]).map(r => {
            const stats = data.regions[r];
            return (
              <div key={r} className="p-3 rounded-lg border border-border/30 bg-secondary/10">
                <div className={`w-full h-1 rounded-full bg-gradient-to-r ${regionColors[r] || "from-zinc-500 to-zinc-400"} mb-2`} />
                <p className="text-xs font-bold">{r}</p>
                <p className="text-lg font-black text-foreground">{stats.countries} <span className="text-[10px] text-muted-foreground font-normal">دولة</span></p>
                <p className="text-[10px] text-muted-foreground">{formatNum(stats.records)} سجل</p>
              </div>
            );
          })}
        </div>
      </ResultCard>

      <ResultCard title={`جميع الدول (${data.countries.length})`} icon={<Globe className="w-4 h-4 text-emerald-400" />} accent="bg-emerald-500/5">
        <div className="max-h-[500px] overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-card z-10">
              <tr className="border-b border-border text-muted-foreground">
                <th className="py-2 text-right pr-2">الدولة</th>
                <th className="py-2 text-right">الكود</th>
                <th className="py-2 text-right">الاتصال</th>
                <th className="py-2 text-right">المنطقة</th>
                <th className="py-2 text-right">السجلات</th>
                <th className="py-2 text-right">التغطية</th>
              </tr>
            </thead>
            <tbody>
              {data.countries.map((c: any) => (
                <tr key={c.code} className="border-b border-border/20 hover:bg-secondary/20 transition-colors">
                  <td className="py-1.5 pr-2 font-medium">{c.nameAr || c.name}</td>
                  <td className="py-1.5 font-mono text-muted-foreground">{c.code}</td>
                  <td className="py-1.5 font-mono text-primary" dir="ltr">{c.dialCode}</td>
                  <td className="py-1.5 text-muted-foreground">{c.region}</td>
                  <td className="py-1.5 font-bold">{formatNum(c.records)}</td>
                  <td className="py-1.5">
                    <span className={`text-[9px] px-1.5 py-0.5 rounded border ${coverageColors[c.coverage] || coverageColors.basic}`}>
                      {c.coverage === "premium" ? "ممتاز" : c.coverage === "standard" ? "قياسي" : "أساسي"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </ResultCard>
    </div>
  );
}

function DataImportTab() {
  const [importMode, setImportMode] = useState<"csv" | "gdrive" | "storage" | "supabase">("csv");
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [sourceName, setSourceName] = useState("");
  const [supabaseUrl, setSupabaseUrl] = useState("");
  const [supabaseTable, setSupabaseTable] = useState("");
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<any>(null);

  const statsQuery = trpc.osint.importStats.useQuery();
  const gdFilesQuery = trpc.osint.listGoogleDriveFiles.useQuery(undefined, { enabled: importMode === "gdrive" });
  const storageFilesQuery = trpc.osint.listObjectStorageFiles.useQuery(undefined, { enabled: importMode === "storage" });

  const csvMut = trpc.osint.importFromCSV.useMutation();
  const gdMut = trpc.osint.importFromGoogleDrive.useMutation();
  const storageMut = trpc.osint.importFromObjectStorage.useMutation();
  const supabaseMut = trpc.osint.importFromSupabase.useMutation();
  const listTablesMut = trpc.osint.listSupabaseTables.useMutation();
  const deleteSourceMut = trpc.osint.deleteBySource.useMutation();
  const clearAllMut = trpc.osint.clearAllContacts.useMutation();

  const [tables, setTables] = useState<string[]>([]);

  const handleCSVUpload = async () => {
    if (!csvFile || !sourceName.trim()) { toast.error("اختر ملف CSV وأدخل اسم المصدر"); return; }
    setImporting(true);
    try {
      const text = await csvFile.text();
      const result = await csvMut.mutateAsync({ csvContent: text, sourceName: sourceName.trim() });
      setImportResult(result);
      statsQuery.refetch();
      if (result.imported > 0) toast.success(`تم استيراد ${result.imported} سجل`);
      else toast("لم يتم استيراد سجلات جديدة", { icon: "ℹ️" });
    } catch (e: any) { toast.error(e.message); }
    setImporting(false);
  };

  const handleGDriveImport = async (fileId: string, fileName: string) => {
    setImporting(true);
    try {
      const result = await gdMut.mutateAsync({ fileId, sourceName: `GoogleDrive:${fileName}` });
      setImportResult(result);
      statsQuery.refetch();
      if (result.imported > 0) toast.success(`تم استيراد ${result.imported} سجل من Google Drive`);
    } catch (e: any) { toast.error(e.message); }
    setImporting(false);
  };

  const handleStorageImport = async (filePath: string) => {
    setImporting(true);
    try {
      const result = await storageMut.mutateAsync({ filePath });
      setImportResult(result);
      statsQuery.refetch();
      if (result.imported > 0) toast.success(`تم استيراد ${result.imported} سجل`);
    } catch (e: any) { toast.error(e.message); }
    setImporting(false);
  };

  const handleSupabaseImport = async () => {
    if (!supabaseUrl || !supabaseTable) { toast.error("أدخل رابط الاتصال واسم الجدول"); return; }
    setImporting(true);
    try {
      const result = await supabaseMut.mutateAsync({ connectionUrl: supabaseUrl, tableName: supabaseTable, sourceName: `Supabase:${supabaseTable}` });
      setImportResult(result);
      statsQuery.refetch();
      if (result.imported > 0) toast.success(`تم استيراد ${result.imported} سجل من Supabase`);
    } catch (e: any) { toast.error(e.message); }
    setImporting(false);
  };

  const handleListTables = async () => {
    if (!supabaseUrl) { toast.error("أدخل رابط الاتصال أولاً"); return; }
    try {
      const t = await listTablesMut.mutateAsync({ connectionUrl: supabaseUrl });
      setTables(t);
      if (t.length === 0) toast("لا توجد جداول", { icon: "ℹ️" });
    } catch (e: any) { toast.error(e.message); }
  };

  const handleDeleteSource = async (source: string) => {
    if (!confirm(`هل تريد حذف جميع السجلات من مصدر: ${source}؟`)) return;
    try {
      const r = await deleteSourceMut.mutateAsync({ source });
      toast.success(`تم حذف ${r.deleted} سجل`);
      statsQuery.refetch();
    } catch (e: any) { toast.error(e.message); }
  };

  const modes = [
    { id: "csv" as const, icon: FileSpreadsheet, label: "رفع CSV", color: "from-blue-500 to-cyan-500" },
    { id: "gdrive" as const, icon: CloudDownload, label: "Google Drive", color: "from-green-500 to-emerald-500" },
    { id: "storage" as const, icon: HardDrive, label: "Object Storage", color: "from-violet-500 to-purple-500" },
    { id: "supabase" as const, icon: Database, label: "Supabase / PostgreSQL", color: "from-orange-500 to-red-500" },
  ];

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-br from-cyan-500/5 to-blue-500/5 border border-cyan-500/20 rounded-2xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shrink-0 shadow-lg shadow-cyan-500/20">
            <CloudDownload className="w-7 h-7 text-white" />
          </div>
          <div>
            <h2 className="font-black text-lg">استيراد البيانات السحابي</h2>
            <p className="text-xs text-muted-foreground">ربط وتحميل البيانات من مصادر متعددة إلى قاعدة البيانات المحلية</p>
          </div>
        </div>

        {statsQuery.data && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
            <div className="bg-card/60 border border-border rounded-xl p-3 text-center">
              <p className="text-2xl font-black text-primary">{formatNum(statsQuery.data.totalContacts)}</p>
              <p className="text-[10px] text-muted-foreground">جهات اتصال</p>
            </div>
            <div className="bg-card/60 border border-border rounded-xl p-3 text-center">
              <p className="text-2xl font-black text-emerald-400">{statsQuery.data.totalCountries}</p>
              <p className="text-[10px] text-muted-foreground">دولة</p>
            </div>
            <div className="bg-card/60 border border-border rounded-xl p-3 text-center">
              <p className="text-2xl font-black text-amber-400">{statsQuery.data.sources.length}</p>
              <p className="text-[10px] text-muted-foreground">مصادر</p>
            </div>
            <div className="bg-card/60 border border-border rounded-xl p-3 text-center">
              <p className="text-2xl font-black text-violet-400">4</p>
              <p className="text-[10px] text-muted-foreground">قنوات استيراد</p>
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-5">
          {modes.map(m => (
            <button key={m.id} onClick={() => setImportMode(m.id)}
              className={`flex flex-col items-center gap-1.5 p-3 rounded-xl border transition-all ${importMode === m.id ? "bg-primary/10 border-primary/40 shadow-lg" : "border-border hover:border-primary/20"}`}>
              <div className={`w-9 h-9 rounded-lg bg-gradient-to-br ${m.color} flex items-center justify-center`}>
                <m.icon className="w-4 h-4 text-white" />
              </div>
              <span className="text-[10px] font-medium">{m.label}</span>
            </button>
          ))}
        </div>

        {importMode === "csv" && (
          <div className="space-y-3">
            <div className="border-2 border-dashed border-border rounded-xl p-6 text-center hover:border-primary/40 transition-colors">
              <input type="file" accept=".csv" onChange={e => setCsvFile(e.target.files?.[0] || null)} className="hidden" id="csv-upload" />
              <label htmlFor="csv-upload" className="cursor-pointer space-y-2 block">
                <Upload className="w-8 h-8 mx-auto text-muted-foreground" />
                <p className="text-sm font-medium">{csvFile ? csvFile.name : "اسحب ملف CSV أو انقر للاختيار"}</p>
                <p className="text-[10px] text-muted-foreground">يدعم: phone, name, carrier, location, country_code, source</p>
              </label>
            </div>
            <input value={sourceName} onChange={e => setSourceName(e.target.value)} placeholder="اسم المصدر (مثال: Truecaller_Dump_2026)"
              className="w-full bg-secondary/50 border border-border rounded-lg px-4 py-2.5 text-sm" />
            <Button onClick={handleCSVUpload} disabled={importing || !csvFile} className="w-full">
              {importing ? <Loader2 className="w-4 h-4 animate-spin ml-2" /> : <Upload className="w-4 h-4 ml-2" />}
              رفع واستيراد
            </Button>
          </div>
        )}

        {importMode === "gdrive" && (
          <div className="space-y-3">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm font-medium">ملفات Google Drive (CSV & Sheets)</p>
              <Button size="sm" variant="outline" onClick={() => gdFilesQuery.refetch()} disabled={gdFilesQuery.isRefetching}>
                <RefreshCw className={`w-3 h-3 ml-1 ${gdFilesQuery.isRefetching ? "animate-spin" : ""}`} /> تحديث
              </Button>
            </div>
            {gdFilesQuery.isLoading && <div className="py-8 text-center"><Loader2 className="w-6 h-6 animate-spin mx-auto text-primary" /></div>}
            {gdFilesQuery.data && gdFilesQuery.data.length === 0 && (
              <div className="py-6 text-center text-sm text-muted-foreground">لا توجد ملفات CSV أو Sheets في Google Drive</div>
            )}
            <div className="max-h-64 overflow-y-auto space-y-1.5">
              {gdFilesQuery.data?.map((file: any) => (
                <div key={file.id} className="flex items-center justify-between bg-card border border-border rounded-lg px-3 py-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <FileSpreadsheet className="w-4 h-4 text-green-400 shrink-0" />
                    <div className="min-w-0">
                      <p className="text-xs font-medium truncate">{file.name}</p>
                      <p className="text-[9px] text-muted-foreground">{file.mimeType?.includes("spreadsheet") ? "Google Sheets" : "CSV"} • {file.modifiedTime?.slice(0, 10)}</p>
                    </div>
                  </div>
                  <Button size="sm" variant="outline" onClick={() => handleGDriveImport(file.id, file.name)} disabled={importing}>
                    {importing ? <Loader2 className="w-3 h-3 animate-spin" /> : <CloudDownload className="w-3 h-3" />}
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}

        {importMode === "storage" && (
          <div className="space-y-3">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm font-medium">ملفات Object Storage</p>
              <Button size="sm" variant="outline" onClick={() => storageFilesQuery.refetch()}>
                <RefreshCw className="w-3 h-3 ml-1" /> تحديث
              </Button>
            </div>
            {storageFilesQuery.isLoading && <div className="py-8 text-center"><Loader2 className="w-6 h-6 animate-spin mx-auto text-primary" /></div>}
            {storageFilesQuery.data && storageFilesQuery.data.length === 0 && (
              <div className="py-6 text-center space-y-2">
                <FolderOpen className="w-8 h-8 mx-auto text-muted-foreground" />
                <p className="text-sm text-muted-foreground">لا توجد ملفات بعد — ارفع ملفات CSV عبر تبويب "رفع CSV"</p>
              </div>
            )}
            <div className="max-h-64 overflow-y-auto space-y-1.5">
              {storageFilesQuery.data?.map((file: any) => (
                <div key={file.name} className="flex items-center justify-between bg-card border border-border rounded-lg px-3 py-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <HardDrive className="w-4 h-4 text-violet-400 shrink-0" />
                    <div className="min-w-0">
                      <p className="text-xs font-medium truncate">{file.name.replace("osint-data/", "")}</p>
                      <p className="text-[9px] text-muted-foreground">{(file.size / 1024).toFixed(1)} KB • {file.updated?.slice(0, 10)}</p>
                    </div>
                  </div>
                  <Button size="sm" variant="outline" onClick={() => handleStorageImport(file.name)} disabled={importing}>
                    {importing ? <Loader2 className="w-3 h-3 animate-spin" /> : <CloudDownload className="w-3 h-3" />}
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}

        {importMode === "supabase" && (
          <div className="space-y-3">
            <input value={supabaseUrl} onChange={e => setSupabaseUrl(e.target.value)} placeholder="postgresql://user:pass@host:5432/dbname"
              className="w-full bg-secondary/50 border border-border rounded-lg px-4 py-2.5 text-sm font-mono" dir="ltr" />
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={handleListTables} disabled={listTablesMut.isPending}>
                {listTablesMut.isPending ? <Loader2 className="w-3 h-3 animate-spin ml-1" /> : <Database className="w-3 h-3 ml-1" />}
                عرض الجداول
              </Button>
              {tables.length > 0 && (
                <select value={supabaseTable} onChange={e => setSupabaseTable(e.target.value)}
                  className="flex-1 bg-secondary/50 border border-border rounded-lg px-3 py-1.5 text-sm">
                  <option value="">اختر جدول...</option>
                  {tables.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              )}
            </div>
            {!tables.length && (
              <input value={supabaseTable} onChange={e => setSupabaseTable(e.target.value)} placeholder="اسم الجدول (contacts, users, etc.)"
                className="w-full bg-secondary/50 border border-border rounded-lg px-4 py-2.5 text-sm" dir="ltr" />
            )}
            <Button onClick={handleSupabaseImport} disabled={importing || !supabaseUrl || !supabaseTable} className="w-full">
              {importing ? <Loader2 className="w-4 h-4 animate-spin ml-2" /> : <Database className="w-4 h-4 ml-2" />}
              استيراد من Supabase
            </Button>
          </div>
        )}
      </div>

      {importResult && (
        <ResultCard title="نتيجة الاستيراد" icon={<Check className="w-4 h-4 text-emerald-400" />} accent="bg-emerald-500/10">
          <DataRow label="المصدر" value={importResult.source} />
          <DataRow label="إجمالي المحلل" value={importResult.totalParsed} />
          <DataRow label="تم الاستيراد" value={importResult.imported} />
          <DataRow label="تم التجاوز (مكرر)" value={importResult.skipped} />
          <DataRow label="التاريخ" value={importResult.timestamp?.slice(0, 19)} />
          {importResult.errors?.length > 0 && (
            <div className="mt-2 space-y-1">
              {importResult.errors.map((e: string, i: number) => (
                <p key={i} className="text-[10px] text-red-400">{e}</p>
              ))}
            </div>
          )}
        </ResultCard>
      )}

      {statsQuery.data && statsQuery.data.sources.length > 0 && (
        <ResultCard title="مصادر البيانات المحفوظة" icon={<Database className="w-4 h-4 text-primary" />}>
          <div className="space-y-1.5">
            {statsQuery.data.sources.map((s: any) => (
              <div key={s.source} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono">{s.source}</span>
                  <span className="text-[9px] bg-primary/10 text-primary px-2 py-0.5 rounded-full">{s.count} سجل</span>
                </div>
                <button onClick={() => handleDeleteSource(s.source)} className="p-1 text-red-400 hover:bg-red-500/10 rounded">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </ResultCard>
      )}
    </div>
  );
}

function CallerIDTab() {
  const [phone, setPhone] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const localMut = trpc.osint.phoneLocalLookup.useMutation();

  const handleSearch = useCallback(async () => {
    if (!phone.trim()) { toast.error("أدخل رقم الهاتف"); return; }
    setLoading(true); setResult(null);
    try {
      const data = await localMut.mutateAsync({ phone: phone.trim() });
      setResult(data);
      if (data.found) toast.success(`تم العثور على ${data.totalResults} نتيجة`);
      else toast("الرقم غير موجود في القاعدة المحلية", { icon: "ℹ️" });
    } catch (e: any) { toast.error(e.message); }
    finally { setLoading(false); }
  }, [phone]);

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-br from-amber-500/5 to-orange-500/5 border border-amber-500/20 rounded-2xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-amber-500 to-orange-500 flex items-center justify-center shrink-0 shadow-lg shadow-amber-500/20">
            <Fingerprint className="w-7 h-7 text-white" />
          </div>
          <div>
            <h2 className="font-black text-lg">Caller ID — معرّف المتصل</h2>
            <p className="text-xs text-muted-foreground">بحث في قاعدة البيانات المحلية: Infgety GCC + Truecaller + Dalil + Getcontact</p>
          </div>
        </div>

        <div className="flex gap-2">
          <input value={phone} onChange={e => setPhone(e.target.value)} placeholder="+966501234567"
            onKeyDown={e => { if (e.key === "Enter") handleSearch(); }}
            className="flex-1 bg-background/80 border border-border rounded-xl px-4 py-3 text-sm font-mono focus:ring-2 focus:ring-amber-500/50 placeholder:text-muted-foreground/50" dir="ltr" />
          <Button onClick={handleSearch} disabled={loading || !phone.trim()} className="px-6 gap-2 bg-gradient-to-r from-amber-500 to-orange-500 text-white hover:from-amber-600 hover:to-orange-600">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            بحث
          </Button>
        </div>

        <div className="flex flex-wrap gap-2 mt-3">
          {["+966505123456", "+971501112233", "+201001234567", "+905551234567", "+12025550199"].map(num => (
            <button key={num} onClick={() => { setPhone(num); }} className="text-[10px] px-2 py-1 rounded-lg border border-border/30 bg-background/50 hover:bg-amber-500/10 hover:border-amber-500/30 transition-all font-mono" dir="ltr">{num}</button>
          ))}
        </div>
      </div>

      {result && (
        <div className="space-y-4">
          {result.found ? (
            <ResultCard title={`تم العثور على ${result.totalResults} نتيجة`} icon={<Check className="w-4 h-4 text-emerald-400" />} accent="bg-emerald-500/5">
              <div className="space-y-3">
                {result.results.map((r: any, i: number) => (
                  <div key={i} className="p-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center text-white font-bold text-sm">
                          {r.name?.charAt(0) || "?"}
                        </div>
                        <div>
                          <p className="font-bold text-sm">{r.name}</p>
                          <p className="text-[10px] text-muted-foreground font-mono" dir="ltr">{r.phone}</p>
                        </div>
                      </div>
                      <CopyBtn text={`${r.name} - ${r.phone}`} />
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                      <div className="flex items-center gap-1.5 text-xs"><Wifi className="w-3 h-3 text-blue-400" /><span className="text-muted-foreground">الشبكة:</span><span className="font-medium">{r.carrier}</span></div>
                      <div className="flex items-center gap-1.5 text-xs"><MapPin className="w-3 h-3 text-red-400" /><span className="text-muted-foreground">الموقع:</span><span className="font-medium">{r.location}</span></div>
                      <div className="flex items-center gap-1.5 text-xs"><Globe className="w-3 h-3 text-emerald-400" /><span className="text-muted-foreground">الدولة:</span><span className="font-medium">{r.country}</span></div>
                      <div className="flex items-center gap-1.5 text-xs"><Signal className="w-3 h-3 text-violet-400" /><span className="text-muted-foreground">النوع:</span><span className="font-medium">{r.lineType}</span></div>
                      <div className="flex items-center gap-1.5 text-xs"><Database className="w-3 h-3 text-amber-400" /><span className="text-muted-foreground">المصدر:</span><span className="font-medium text-amber-400">{r.source?.replace(/_/g, " ")}</span></div>
                    </div>
                  </div>
                ))}
              </div>
            </ResultCard>
          ) : (
            <ResultCard title="لم يُعثر على نتائج" icon={<AlertTriangle className="w-4 h-4 text-yellow-400" />} accent="bg-yellow-500/5">
              <p className="text-xs text-muted-foreground">{result.suggestion}</p>
              {result.countryInfo && (
                <div className="mt-3 p-3 rounded-lg border border-border/30 bg-secondary/10 space-y-1">
                  <p className="text-xs font-bold text-primary">معلومات الدولة المكتشفة:</p>
                  <DataRow label="الدولة" value={`${result.countryInfo.countryAr} (${result.countryInfo.country})`} />
                  <DataRow label="المنطقة" value={result.countryInfo.region} />
                  <DataRow label="مستوى التغطية" value={result.countryInfo.coverage === "premium" ? "ممتاز" : result.countryInfo.coverage === "standard" ? "قياسي" : "أساسي"} />
                  <DataRow label="السجلات المتوفرة" value={formatNum(result.countryInfo.recordsInDB)} />
                </div>
              )}
            </ResultCard>
          )}
        </div>
      )}
    </div>
  );
}

export default function OSINTPage() {
  const { isAuthenticated, loading: authLoading } = useAuth();
  const [activeTab, setActiveTab] = useState<Tab>("tools");
  const [activeTool, setActiveTool] = useState<Tool>("ip");
  const [input, setInput] = useState("");
  const [dnsType, setDnsType] = useState("A");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const ipMut = trpc.osint.ipLookup.useMutation();
  const whoisMut = trpc.osint.whoisLookup.useMutation();
  const dnsMut = trpc.osint.dnsLookup.useMutation();
  const emailMut = trpc.osint.emailBreachCheck.useMutation();
  const usernameMut = trpc.osint.usernameSearch.useMutation();
  const phoneMut = trpc.osint.phoneLookup.useMutation();
  const techMut = trpc.osint.techLookup.useMutation();
  const sslMut = trpc.osint.sslLookup.useMutation();
  const subMut = trpc.osint.subdomainSearch.useMutation();

  const handleSearch = useCallback(async () => {
    if (!input.trim()) { toast.error("أدخل قيمة البحث"); return; }
    setLoading(true); setResult(null);
    try {
      let data: any;
      switch (activeTool) {
        case "ip": data = await ipMut.mutateAsync({ ip: input }); break;
        case "whois": data = await whoisMut.mutateAsync({ domain: input }); break;
        case "dns": data = await dnsMut.mutateAsync({ domain: input, type: dnsType }); break;
        case "email": data = await emailMut.mutateAsync({ email: input }); break;
        case "username": data = await usernameMut.mutateAsync({ username: input }); break;
        case "phone": data = await phoneMut.mutateAsync({ phone: input }); break;
        case "tech": data = await techMut.mutateAsync({ url: input }); break;
        case "ssl": data = await sslMut.mutateAsync({ domain: input }); break;
        case "subdomain": data = await subMut.mutateAsync({ domain: input }); break;
      }
      setResult(data);
      toast.success("تم البحث بنجاح");
    } catch (e: any) { toast.error(e.message || "فشل البحث"); }
    finally { setLoading(false); }
  }, [activeTool, input, dnsType]);

  const toolConfig = TOOLS.find(t => t.id === activeTool)!;

  if (authLoading) return <div className="h-screen flex items-center justify-center bg-background"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
  if (!isAuthenticated) return (
    <div className="h-screen flex items-center justify-center bg-background p-4">
      <div className="bg-card border border-border rounded-2xl p-8 max-w-md text-center space-y-4">
        <Shield className="w-16 h-16 mx-auto text-red-400" /><h2 className="text-2xl font-bold">OSINT Intelligence</h2>
        <p className="text-sm text-muted-foreground">نظام استخبارات المصادر المفتوحة — سجل الدخول للوصول</p>
        <Button asChild className="w-full"><a href={getLoginUrl()}>تسجيل الدخول</a></Button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">
      <header className="h-14 bg-card/80 backdrop-blur-lg border-b border-border flex items-center justify-between px-4 sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <Link href="/" className="text-muted-foreground hover:text-primary transition-colors"><Home className="w-4 h-4" /></Link>
          <div className="w-px h-6 bg-border" />
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div>
            <span className="font-black text-sm tracking-tight">HAYO OSINT</span>
            <span className="text-[9px] bg-red-500/10 text-red-400 px-2 py-0.5 rounded-full mr-2">v2.0</span>
          </div>
        </div>
        <div className="flex items-center gap-1 bg-secondary/50 rounded-lg p-0.5">
          {[
            { id: "tools" as Tab, label: "أدوات OSINT", icon: Search },
            { id: "callerid" as Tab, label: "معرّف المتصل", icon: Fingerprint },
            { id: "coverage" as Tab, label: "التغطية", icon: BarChart3 },
            { id: "import" as Tab, label: "استيراد البيانات", icon: CloudDownload },
          ].map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${activeTab === tab.id ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>
              <tab.icon className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{tab.label}</span>
            </button>
          ))}
        </div>
      </header>

      <div className="max-w-6xl mx-auto p-4 md:p-6">
        {activeTab === "coverage" && <CoverageTab />}
        {activeTab === "callerid" && <CallerIDTab />}
        {activeTab === "import" && <DataImportTab />}
        {activeTab === "tools" && (
          <div className="space-y-6">
            <div className="grid grid-cols-3 sm:grid-cols-5 lg:grid-cols-9 gap-2">
              {TOOLS.map(tool => {
                const Icon = tool.icon;
                const active = activeTool === tool.id;
                return (
                  <button key={tool.id} onClick={() => { setActiveTool(tool.id); setResult(null); setInput(""); }}
                    className={`flex flex-col items-center gap-1.5 p-3 rounded-xl border transition-all ${active ? "bg-primary/10 border-primary/40 shadow-lg shadow-primary/10" : "border-border hover:border-primary/20 hover:bg-secondary/30"}`}>
                    <div className={`w-9 h-9 rounded-lg bg-gradient-to-br ${tool.color} flex items-center justify-center`}>
                      <Icon className="w-4 h-4 text-white" />
                    </div>
                    <span className="text-[10px] font-medium text-center leading-tight">{tool.label}</span>
                  </button>
                );
              })}
            </div>

            <div className="bg-card border border-border rounded-2xl p-5 space-y-4">
              <div className="flex items-center gap-3">
                <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${toolConfig.color} flex items-center justify-center shrink-0`}>
                  <toolConfig.icon className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h2 className="font-bold text-lg">{toolConfig.label}</h2>
                  <p className="text-xs text-muted-foreground">{toolConfig.desc}</p>
                </div>
              </div>
              <div className="flex gap-2">
                <input value={input} onChange={e => setInput(e.target.value)} placeholder={toolConfig.placeholder}
                  onKeyDown={e => { if (e.key === "Enter") handleSearch(); }}
                  className="flex-1 bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm font-mono focus:ring-2 focus:ring-primary/50" dir="ltr" />
                {activeTool === "dns" && (
                  <select value={dnsType} onChange={e => setDnsType(e.target.value)} className="bg-secondary/50 border border-border rounded-xl px-3 text-xs">
                    {["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV"].map(t => <option key={t}>{t}</option>)}
                  </select>
                )}
                <Button onClick={handleSearch} disabled={loading || !input.trim()} className={`px-6 gap-2 bg-gradient-to-r ${toolConfig.color} text-white`}>
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  {loading ? "جاري..." : "بحث"}
                </Button>
              </div>
            </div>

            {result && (
              <div className="space-y-4">
                {activeTool === "ip" && (
                  <ResultCard title={`موقع IP: ${result.query}`} icon={<MapPin className="w-4 h-4 text-red-400" />}>
                    <div className="grid grid-cols-2 gap-x-6">
                      <DataRow label="الدولة" value={`${result.country} (${result.countryCode})`} />
                      <DataRow label="المنطقة" value={result.regionName} />
                      <DataRow label="المدينة" value={result.city} />
                      <DataRow label="الرمز البريدي" value={result.zip} />
                      <DataRow label="خط العرض" value={result.lat} copyable />
                      <DataRow label="خط الطول" value={result.lon} copyable />
                      <DataRow label="المنطقة الزمنية" value={result.timezone} />
                      <DataRow label="مزود الخدمة" value={result.isp} />
                      <DataRow label="المنظمة" value={result.org} />
                      <DataRow label="AS Number" value={result.as} copyable />
                      <DataRow label="موبايل" value={result.mobile ? "نعم" : "لا"} />
                      <DataRow label="بروكسي/VPN" value={result.proxy ? "نعم" : "لا"} />
                      <DataRow label="استضافة" value={result.hosting ? "نعم" : "لا"} />
                    </div>
                    <a href={`https://www.google.com/maps?q=${result.lat},${result.lon}`} target="_blank" rel="noopener"
                      className="flex items-center gap-1 text-xs text-primary mt-3 hover:underline"><MapPin className="w-3 h-3" /> فتح في Google Maps <ExternalLink className="w-3 h-3" /></a>
                  </ResultCard>
                )}

                {activeTool === "whois" && (
                  <ResultCard title={`WHOIS: ${result.domain}`} icon={<Globe className="w-4 h-4 text-blue-400" />}>
                    <DataRow label="الدومين" value={result.domain} copyable />
                    <DataRow label="المسجّل" value={result.registrar} />
                    <DataRow label="تاريخ التسجيل" value={result.created} />
                    <DataRow label="تاريخ الانتهاء" value={result.expires} />
                    <DataRow label="آخر تحديث" value={result.updated} />
                    <DataRow label="الحالة" value={result.status?.join(", ")} />
                    <DataRow label="Nameservers" value={result.nameservers?.join(", ")} />
                  </ResultCard>
                )}

                {activeTool === "dns" && (
                  <ResultCard title={`DNS (${result.type}): ${result.domain}`} icon={<Server className="w-4 h-4 text-emerald-400" />}>
                    {result.records?.length > 0 ? result.records.map((r: any, i: number) => (
                      <div key={i} className="flex items-center justify-between py-1 border-b border-border/30">
                        <span className="text-xs text-muted-foreground">{r.name}</span>
                        <span className="text-xs font-mono text-foreground">{r.data}</span>
                        <span className="text-[10px] text-muted-foreground">TTL: {r.ttl}</span>
                      </div>
                    )) : <p className="text-xs text-muted-foreground">لا توجد سجلات {result.type}</p>}
                  </ResultCard>
                )}

                {activeTool === "email" && (
                  <ResultCard title={`فحص تسريب: ${result.email}`} icon={<Mail className="w-4 h-4 text-violet-400" />}>
                    <div className={`p-3 rounded-lg ${result.breached ? "bg-red-500/10 border border-red-500/20" : "bg-emerald-500/10 border border-emerald-500/20"}`}>
                      <p className={`text-sm font-bold ${result.breached ? "text-red-400" : "text-emerald-400"}`}>
                        {result.breached ? `تم العثور على ${result.breachCount} تسريب!` : "آمن — لم يُعثر على تسريبات"}
                      </p>
                    </div>
                    {result.breaches?.length > 0 && (
                      <div className="space-y-1 mt-2">{result.breaches.map((b: any, i: number) => (
                        <span key={i} className="inline-block text-[10px] px-2 py-1 rounded bg-red-500/10 text-red-400 ml-1">{b.Name || b}</span>
                      ))}</div>
                    )}
                    {result.note && <p className="text-[10px] text-muted-foreground mt-2">{result.note}</p>}
                  </ResultCard>
                )}

                {activeTool === "username" && (
                  <ResultCard title={`بحث: @${result.username}`} icon={<User className="w-4 h-4 text-pink-400" />}>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {result.sites?.map((site: any, i: number) => (
                        <a key={i} href={site.url} target="_blank" rel="noopener"
                          className={`flex items-center gap-2 p-2.5 rounded-lg border transition-all hover:shadow ${site.found === true ? "bg-emerald-500/5 border-emerald-500/20" : site.found === false ? "bg-red-500/5 border-red-500/20 opacity-50" : "border-border hover:border-primary/20"}`}>
                          <span className="text-xs font-bold">{site.name}</span>
                          {site.found === true && <Check className="w-3 h-3 text-emerald-400 mr-auto" />}
                          {site.found === false && <X className="w-3 h-3 text-red-400 mr-auto" />}
                          {site.found === null && <ExternalLink className="w-3 h-3 text-muted-foreground mr-auto" />}
                          {site.info?.name && <span className="text-[10px] text-muted-foreground">{site.info.name}</span>}
                        </a>
                      ))}
                    </div>
                  </ResultCard>
                )}

                {activeTool === "phone" && (
                  <ResultCard title={`فحص رقم: ${result.phone}`} icon={<Phone className="w-4 h-4 text-amber-400" />}>
                    {result.combinedResult?.found ? (
                      <div className="space-y-2">
                        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                          <p className="text-sm font-bold text-emerald-400">تم العثور على الرقم في القاعدة المحلية</p>
                        </div>
                        <DataRow label="الاسم" value={result.combinedResult.name} copyable />
                        <DataRow label="الشبكة" value={result.combinedResult.carrier} />
                        <DataRow label="الموقع" value={result.combinedResult.location} />
                        <DataRow label="الدولة" value={result.combinedResult.country} />
                        <DataRow label="النوع" value={result.combinedResult.lineType} />
                        <DataRow label="المصدر" value={result.combinedResult.source?.replace(/_/g, " ")} />
                        {result.localDB?.results?.length > 1 && (
                          <div className="mt-2 pt-2 border-t border-border/30">
                            <p className="text-[10px] text-muted-foreground mb-1">كل النتائج ({result.localDB.totalResults}):</p>
                            {result.localDB.results.map((r: any, i: number) => (
                              <div key={i} className="text-[10px] py-0.5 font-mono">{r.name} — {r.carrier} — {r.location}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="space-y-2">
                        <div className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                          <p className="text-sm text-yellow-400">الرقم غير موجود محلياً — روابط خارجية:</p>
                        </div>
                        {result.external?.manualCheck?.map((url: string, i: number) => (
                          <a key={i} href={url} target="_blank" rel="noopener" className="flex items-center gap-2 text-xs text-primary hover:underline">
                            <ExternalLink className="w-3 h-3" /> {url}
                          </a>
                        ))}
                      </div>
                    )}
                  </ResultCard>
                )}

                {activeTool === "tech" && (
                  <ResultCard title={`تقنيات: ${result.domain}`} icon={<Code2 className="w-4 h-4 text-indigo-400" />}>
                    <DataRow label="العنوان" value={result.title} />
                    <DataRow label="الوصف" value={result.metaDesc} />
                    <DataRow label="HTTP Status" value={result.statusCode} />
                    <DataRow label="SSL" value={result.ssl ? "مفعّل" : "غير مفعّل"} />
                    <DataRow label="Server" value={result.headers?.server} />
                    <DataRow label="Powered By" value={result.headers?.["x-powered-by"]} />
                    {result.technologies?.length > 0 && (
                      <div className="mt-2"><p className="text-xs text-muted-foreground mb-1">التقنيات المكتشفة:</p>
                        <div className="flex flex-wrap gap-1">{result.technologies.map((t: string, i: number) => (
                          <span key={i} className="text-[10px] px-2 py-1 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">{t}</span>
                        ))}</div>
                      </div>
                    )}
                  </ResultCard>
                )}

                {activeTool === "ssl" && (
                  <ResultCard title={`شهادات SSL: ${result.domain} (${result.total})`} icon={<Lock className="w-4 h-4 text-emerald-400" />}>
                    {result.certificates?.map((c: any, i: number) => (
                      <div key={i} className="p-2 rounded-lg border border-border/30 space-y-1 mb-2">
                        <DataRow label="الاسم" value={c.commonName} copyable />
                        <DataRow label="المُصدر" value={c.issuer} />
                        <DataRow label="من" value={c.notBefore} />
                        <DataRow label="إلى" value={c.notAfter} />
                      </div>
                    ))}
                  </ResultCard>
                )}

                {activeTool === "subdomain" && (
                  <ResultCard title={`نطاقات فرعية: ${result.domain} (${result.count})`} icon={<Network className="w-4 h-4 text-orange-400" />}>
                    <div className="max-h-64 overflow-y-auto space-y-0.5">
                      {result.subdomains?.map((s: string, i: number) => (
                        <div key={i} className="flex items-center justify-between py-1 border-b border-border/20">
                          <span className="text-xs font-mono text-foreground">{s}</span>
                          <CopyBtn text={s} />
                        </div>
                      ))}
                    </div>
                  </ResultCard>
                )}

                <details className="bg-card border border-border rounded-xl overflow-hidden">
                  <summary className="px-4 py-2 text-xs text-muted-foreground cursor-pointer hover:bg-secondary/30 flex items-center gap-1"><ChevronDown className="w-3 h-3" /> عرض البيانات الخام (JSON)</summary>
                  <pre className="p-4 text-[10px] font-mono text-foreground/60 overflow-x-auto max-h-60" dir="ltr">{JSON.stringify(result, null, 2)}</pre>
                </details>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
