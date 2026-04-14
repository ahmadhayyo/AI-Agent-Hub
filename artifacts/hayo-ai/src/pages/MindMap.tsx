/**
 * HAYO Mind Map — خريطة العقل التفاعلية
 * 🎁 هدية من Claude لأحمد
 * تحوّل أي فكرة لخريطة ذهنية بصرية مع إجراءات مربوطة بأقسام المنصة
 */
import { useState, useCallback } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import {
  Brain, Home, Loader2, Sparkles, ChevronDown, ChevronRight,
  ExternalLink, RefreshCw, Plus, Maximize2, Copy, Lightbulb,
  Send, MessageSquare, X,
} from "lucide-react";

interface MindNode {
  id: string; label: string; description: string; icon: string;
  color: string; type: string; children: MindNode[];
  actionTarget?: string; actionPrompt?: string; depth: number;
}

const COLOR_MAP: Record<string, { bg: string; border: string; text: string }> = {
  blue:   { bg: "bg-blue-500/10", border: "border-blue-500/30", text: "text-blue-400" },
  green:  { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400" },
  amber:  { bg: "bg-amber-500/10", border: "border-amber-500/30", text: "text-amber-400" },
  red:    { bg: "bg-red-500/10", border: "border-red-500/30", text: "text-red-400" },
  purple: { bg: "bg-purple-500/10", border: "border-purple-500/30", text: "text-purple-400" },
  pink:   { bg: "bg-pink-500/10", border: "border-pink-500/30", text: "text-pink-400" },
  cyan:   { bg: "bg-cyan-500/10", border: "border-cyan-500/30", text: "text-cyan-400" },
  teal:   { bg: "bg-teal-500/10", border: "border-teal-500/30", text: "text-teal-400" },
  indigo: { bg: "bg-indigo-500/10", border: "border-indigo-500/30", text: "text-indigo-400" },
  orange: { bg: "bg-orange-500/10", border: "border-orange-500/30", text: "text-orange-400" },
};

const TARGET_LABELS: Record<string, { label: string; href: string; icon: string }> = {
  studies:     { label: "دراسات واستشارات", href: "/studies", icon: "📊" },
  office:      { label: "أعمال مكتبية", href: "/office", icon: "📄" },
  agent:       { label: "وكيل الكود", href: "/agent", icon: "🤖" },
  appbuilder:  { label: "منشئ التطبيقات", href: "/app-builder", icon: "📱" },
  prompt:      { label: "مصنع البرومبت", href: "/prompt-factory", icon: "🪄" },
  trading:     { label: "تحليل الأسواق", href: "/trading", icon: "📈" },
  chat:        { label: "دردشة AI", href: "/chat", icon: "💬" },
  "ea-factory": { label: "EA Factory", href: "/ea-factory", icon: "⚙️" },
};

// Recursive tree node component
function TreeNode({ node, onExpand, onAction, expanded, toggleExpand }: {
  node: MindNode;
  onExpand: (node: MindNode) => void;
  onAction: (target: string, prompt: string) => void;
  expanded: Set<string>;
  toggleExpand: (id: string) => void;
}) {
  const colors = COLOR_MAP[node.color] || COLOR_MAP.blue;
  const isOpen = expanded.has(node.id);
  const hasChildren = node.children && node.children.length > 0;
  const isAction = node.type === "action" && node.actionTarget;

  return (
    <div className="space-y-1">
      <div className={`flex items-start gap-2 p-3 rounded-xl border ${colors.border} ${colors.bg} transition-all hover:shadow-md group`}>
        {/* Expand/Collapse */}
        {hasChildren ? (
          <button onClick={() => toggleExpand(node.id)} className="mt-0.5 shrink-0">
            {isOpen ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
          </button>
        ) : (
          <span className="w-4 shrink-0" />
        )}

        {/* Icon */}
        <span className="text-lg shrink-0">{node.icon}</span>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h4 className={`font-bold text-sm ${colors.text}`}>{node.label}</h4>
            {node.type === "action" && <span className="text-[9px] px-1.5 py-0.5 rounded bg-primary/10 text-primary">إجراء</span>}
          </div>
          <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{node.description}</p>

          {/* Action button */}
          {isAction && node.actionTarget && (
            <button onClick={() => onAction(node.actionTarget!, node.actionPrompt || node.description)}
              className="mt-2 flex items-center gap-1.5 text-[10px] px-2.5 py-1 rounded-lg bg-primary/10 text-primary hover:bg-primary/20 transition-colors">
              <Send className="w-3 h-3" />
              أرسل لـ {TARGET_LABELS[node.actionTarget]?.icon} {TARGET_LABELS[node.actionTarget]?.label || node.actionTarget}
            </button>
          )}
        </div>

        {/* Expand button */}
        {!hasChildren && node.type !== "action" && (
          <button onClick={() => onExpand(node)} className="opacity-0 group-hover:opacity-100 shrink-0 p-1 rounded-lg hover:bg-secondary/50 text-muted-foreground" title="توسيع">
            <Plus className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Children */}
      {hasChildren && isOpen && (
        <div className="mr-6 pr-4 border-r-2 border-border/30 space-y-1">
          {node.children.map(child => (
            <TreeNode key={child.id} node={child} onExpand={onExpand} onAction={onAction} expanded={expanded} toggleExpand={toggleExpand} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function MindMap() {
  const { isAuthenticated, loading: authLoading } = useAuth();
  const { t } = useTranslation();
  const [, navigate] = useLocation();
  const [idea, setIdea] = useState("");
  const [notes, setNotes] = useState("");
  const [depth, setDepth] = useState(3);
  const [mapData, setMapData] = useState<{ root: MindNode; totalNodes: number; suggestions: string[]; summary: string } | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set(["root"]));

  const generateMut = trpc.mindMap.generate.useMutation({
    onSuccess: (data) => {
      setMapData(data as any);
      // Auto-expand first 2 levels
      const ids = new Set<string>();
      function collect(node: MindNode, d: number) { ids.add(node.id); if (d < 2 && node.children) node.children.forEach(c => collect(c, d + 1)); }
      if (data.root) collect(data.root as any, 0);
      setExpanded(ids);
      toast.success(`✅ خريطة ذهنية بـ ${data.totalNodes} عقدة!`);
    },
    onError: (e) => toast.error(e.message),
  });

  const expandMut = trpc.mindMap.expand.useMutation();

  const toggleExpand = useCallback((id: string) => {
    setExpanded(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }, []);

  const handleExpand = useCallback(async (node: MindNode) => {
    toast.info("⏳ AI يوسّع العقدة...");
    try {
      const children = await expandMut.mutateAsync({ node, parentContext: idea });
      if (!mapData) return;
      // Update tree
      const updateTree = (n: MindNode): MindNode => {
        if (n.id === node.id) return { ...n, children: [...(n.children || []), ...(children as MindNode[])] };
        return { ...n, children: (n.children || []).map(updateTree) };
      };
      setMapData({ ...mapData, root: updateTree(mapData.root), totalNodes: mapData.totalNodes + (children as any[]).length });
      setExpanded(prev => new Set([...prev, node.id]));
      toast.success("تم التوسيع!");
    } catch (e: any) { toast.error(e.message); }
  }, [mapData, idea, expandMut]);

  const handleAction = useCallback((target: string, prompt: string) => {
    const info = TARGET_LABELS[target];
    if (info) {
      toast.success(`🚀 جاري الانتقال لـ ${info.label}...`);
      // Store prompt for the target page
      try { sessionStorage.setItem(`hayo-mindmap-${target}`, prompt); } catch {}
      navigate(info.href);
    }
  }, [navigate]);

  const expandAll = useCallback(() => {
    if (!mapData) return;
    const ids = new Set<string>();
    function collect(n: MindNode) { ids.add(n.id); (n.children || []).forEach(collect); }
    collect(mapData.root);
    setExpanded(ids);
  }, [mapData]);

  if (authLoading) return <div className="h-screen flex items-center justify-center bg-background"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
  if (!isAuthenticated) return (
    <div className="h-screen flex items-center justify-center bg-background p-4">
      <div className="bg-card border border-border rounded-2xl p-8 max-w-md text-center space-y-4">
        <Brain className="w-16 h-16 mx-auto text-primary opacity-60" />
        <h2 className="text-2xl font-bold">Mind Map</h2>
        <Button asChild className="w-full"><a href={getLoginUrl()}>تسجيل الدخول</a></Button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">
      <header className="h-12 bg-card border-b border-border flex items-center justify-between px-4 sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <Link href="/" className="text-muted-foreground hover:text-primary"><Home className="w-4 h-4" /></Link>
          <div className="w-px h-5 bg-border" />
          <Brain className="w-5 h-5 text-primary" />
          <span className="font-bold text-sm">Mind Map</span>
          <span className="text-[9px] bg-primary/10 text-primary px-2 py-0.5 rounded-full">🎁 هدية Claude</span>
        </div>
        <LanguageSwitcher />
      </header>

      <div className="max-w-5xl mx-auto p-6 space-y-6">
        {/* Input */}
        {!mapData && (
          <div className="space-y-6">
            <div className="text-center space-y-3 py-8">
              <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-primary/20 to-violet-500/20">
                <Brain className="w-10 h-10 text-primary" />
              </div>
              <h1 className="text-3xl font-bold">خريطة العقل التفاعلية</h1>
              <p className="text-muted-foreground max-w-xl mx-auto">اكتب أي فكرة — مشروع، مشكلة، خطة — وسيحوّلها AI لخريطة ذهنية بصرية مع إجراءات عملية مربوطة بأقسام المنصة</p>
            </div>

            <div className="bg-card border border-border rounded-2xl p-6 space-y-4">
              <textarea value={idea} onChange={e => setIdea(e.target.value)} rows={3} placeholder="مثال: أريد بناء مطعم سوشي في إسطنبول بميزانية 50,000$ مع تطبيق توصيل..."
                className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm resize-none focus:ring-2 focus:ring-primary/50" />
              <textarea value={notes} onChange={e => setNotes(e.target.value)} rows={2} placeholder="ملاحظات إضافية (اختياري): أركز على... أحتاج تفصيل في..."
                className="w-full bg-secondary/30 border border-border rounded-xl px-4 py-3 text-xs resize-none" />
              <div className="flex items-center gap-3">
                <div className="flex-1">
                  <label className="text-xs text-muted-foreground">عمق التفريع</label>
                  <div className="flex gap-2 mt-1">
                    {[2, 3, 4].map(d => (
                      <button key={d} onClick={() => setDepth(d)} className={`px-3 py-1.5 rounded-lg text-xs font-bold border ${depth === d ? "bg-primary/15 border-primary text-primary" : "border-border text-muted-foreground"}`}>
                        {d} مستويات
                      </button>
                    ))}
                  </div>
                </div>
                <Button onClick={() => generateMut.mutate({ idea, depth, userNotes: notes || undefined })} disabled={generateMut.isPending || idea.trim().length < 5}
                  className="h-12 px-8 gap-2 bg-gradient-to-r from-primary to-violet-600 text-base">
                  {generateMut.isPending ? <><Loader2 className="w-5 h-5 animate-spin" /> AI يفكر...</> : <><Sparkles className="w-5 h-5" /> إنشاء الخريطة</>}
                </Button>
              </div>
            </div>

            {/* Examples */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {[
                "أريد بناء مطعم في إسطنبول بميزانية 50,000$",
                "خطة لإطلاق تطبيق توصيل طعام في السوق العربي",
                "مشروع مزرعة دواجن 20,000 طير مع تصدير",
              ].map(ex => (
                <button key={ex} onClick={() => setIdea(ex)} className="text-right text-xs p-3 rounded-xl border border-border hover:border-primary/30 hover:bg-primary/5 transition-all text-muted-foreground">
                  💡 {ex}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Mind Map Result */}
        {mapData && (
          <div className="space-y-6">
            {/* Header */}
            <div className="bg-gradient-to-r from-primary/10 to-violet-500/10 border border-primary/20 rounded-2xl p-5">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h2 className="font-bold text-lg flex items-center gap-2"><Brain className="w-5 h-5 text-primary" /> {mapData.root.label}</h2>
                  <p className="text-sm text-muted-foreground mt-1">{mapData.summary}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs bg-primary/10 text-primary px-3 py-1 rounded-full">{mapData.totalNodes} عقدة</span>
                  <button onClick={expandAll} className="text-xs text-primary hover:underline flex items-center gap-1"><Maximize2 className="w-3 h-3" /> فتح الكل</button>
                </div>
              </div>
              {mapData.suggestions.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-3">
                  {mapData.suggestions.map((s, i) => (
                    <span key={i} className="text-[10px] px-2 py-1 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">💡 {s}</span>
                  ))}
                </div>
              )}
            </div>

            {/* Tree */}
            <div className="space-y-2">
              <TreeNode node={mapData.root} onExpand={handleExpand} onAction={handleAction} expanded={expanded} toggleExpand={toggleExpand} />
            </div>

            {/* Actions */}
            <div className="flex gap-3 flex-wrap">
              <Button variant="outline" onClick={() => { setMapData(null); setIdea(""); }} className="gap-2"><RefreshCw className="w-4 h-4" /> خريطة جديدة</Button>
              <Button variant="outline" onClick={() => { navigator.clipboard.writeText(JSON.stringify(mapData, null, 2)); toast.success("تم النسخ"); }} className="gap-2"><Copy className="w-4 h-4" /> نسخ JSON</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
