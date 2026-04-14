import { useEffect, useState, useCallback, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Download, Copy, Share2, Eye, Code2, CheckCircle2, Zap,
  FolderArchive, ArrowLeft, Sparkles, Server, Globe, FileCode,
  Home, Clock, Loader2, AlertTriangle, MonitorPlay, Maximize2, Minimize2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Link, useLocation, useSearch } from 'wouter';
import { takePendingProject } from '@/lib/projectStore';
import { toast } from 'sonner';
import JSZip from 'jszip';
import { trpc } from '@/lib/trpc';

interface ProjectFile {
  name: string;
  content: string;
  language?: string;
  size?: number;
}

interface SavedProject {
  id: string;
  name: string;
  description: string;
  files: ProjectFile[];
  createdAt: string;
  category?: string;
  model?: string;
  status?: 'completed' | 'error';
}

function escapeHtml(s: string) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function buildPreviewHtml(files: ProjectFile[]): string {
  const html  = files.find(f => /\.html?$/i.test(f.name));
  const css   = files.filter(f => /\.css$/i.test(f.name));
  const js    = files.filter(f => /\.(js|jsx|ts|tsx)$/i.test(f.name) && !f.name.includes('.min.'));

  if (html) {
    let src = html.content;
    if (css.length) {
      const block = css.map(f => `<style>/* ${f.name} */\n${f.content}</style>`).join('\n');
      src = src.includes('</head>') ? src.replace('</head>', `${block}\n</head>`) : `${block}\n${src}`;
    }
    if (js.length) {
      const block = js.map(f => `<script>/* ${f.name} */\n${f.content}</script>`).join('\n');
      src = src.includes('</body>') ? src.replace('</body>', `${block}\n</body>`) : `${src}\n${block}`;
    }
    return src;
  }

  const cssContent = css.map(f => f.content).join('\n');
  const jsContent  = js.map(f => f.content).join('\n');
  if (cssContent || jsContent) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>${cssContent}</style></head><body><div id="root"></div><script>${jsContent}</script></body></html>`;
  }

  // Non-web project — show code as formatted page
  const body = files.map(f =>
    `<h3 style="color:#818cf8;font-family:monospace;margin:20px 0 8px">${escapeHtml(f.name)}</h3>` +
    `<pre style="background:#1e1e2e;padding:16px;border-radius:8px;overflow-x:auto;color:#cdd6f4;font-size:13px;line-height:1.5">${escapeHtml(f.content.slice(0, 4000))}${f.content.length > 4000 ? '\n\n... (مقتطع)' : ''}</pre>`
  ).join('');
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>body{background:#0f0f23;padding:24px;font-family:system-ui;direction:ltr}</style></head><body>${body}</body></html>`;
}

export default function ProjectCompletionScreen() {
  const [, navigate] = useLocation();
  const search = useSearch();
  const [project, setProject] = useState<SavedProject | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [copied, setCopied] = useState(false);
  const [activeFileIdx, setActiveFileIdx] = useState(0);
  const [isDownloadingZip, setIsDownloadingZip] = useState(false);
  const [completionView, setCompletionView] = useState<'code' | 'preview'>('preview');
  const [previewFullscreen, setPreviewFullscreen] = useState(false);
  const [iframeKey, setIframeKey] = useState(0);

  const githubPushMutation = trpc.automation.githubPush.useMutation();
  const vercelDeployMutation = trpc.automation.vercelDeploy.useMutation();

  // Derive preview HTML early (before early returns) to comply with rules of hooks
  const previewHtml = useMemo(() => buildPreviewHtml(project?.files ?? []), [project]);
  const hasWebFiles = (project?.files ?? []).some(f => /\.(html?|css|js|jsx)$/i.test(f.name));

  useEffect(() => {
    // useSearch() from wouter v3 returns the current query string (without "?")
    // This works correctly inside the Replit iframe, unlike window.location.search
    const params = new URLSearchParams(search);

    // Try to load the project — multiple fallback layers
    const projectId = params.get('id');

    // 0. In-memory store (fastest, no size limit — set right before navigate)
    const pending = takePendingProject();
    if (pending && (!projectId || pending.id === projectId)) {
      setProject(pending);
      return;
    }

    if (projectId) {
      // 1. localStorage (persistent project history)
      try {
        const stored = JSON.parse(localStorage.getItem('hayo-projects') || '[]') as SavedProject[];
        const found = stored.find((p) => p.id === projectId);
        if (found) { setProject(found); return; }
      } catch { /* fallthrough */ }

      // 2. sessionStorage backup
      try {
        const session = JSON.parse(sessionStorage.getItem('hayo-current-project') || 'null') as SavedProject | null;
        if (session && session.id === projectId) { setProject(session); return; }
      } catch { /* fallthrough */ }
    }

    // Try inline JSON from URL param
    const projectData = params.get('project');
    if (projectData) {
      try {
        setProject(JSON.parse(decodeURIComponent(projectData)));
        return;
      } catch { /* fallthrough */ }
    }

    setNotFound(true);
  }, [search]);

  const handleDownloadZip = useCallback(async () => {
    if (!project) return;
    setIsDownloadingZip(true);
    try {
      const zip = new JSZip();
      project.files.forEach((f) => zip.file(f.name, f.content));
      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${project.name.replace(/\s+/g, '-').slice(0, 40)}.zip`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('تم تحميل الملفات كـ ZIP');
    } catch {
      toast.error('فشل تحميل الملفات');
    }
    setIsDownloadingZip(false);
  }, [project]);

  const handleCopyLink = useCallback(() => {
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    toast.success('تم نسخ الرابط');
    setTimeout(() => setCopied(false), 2000);
  }, []);

  const handleShare = useCallback(() => {
    if (!project) return;
    const text = `تحقق من مشروعي الجديد بالذكاء الاصطناعي: ${project.name}`;
    if (navigator.share) {
      navigator.share({ title: project.name, text, url: window.location.href });
    } else {
      navigator.clipboard.writeText(`${text}\n${window.location.href}`);
      toast.success('تم نسخ معلومات المشاركة');
    }
  }, [project]);

  const handleGitHubPush = useCallback(async () => {
    if (!project || project.files.length === 0) return;
    const repoName = project.name.slice(0, 30).replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase() || 'hayo-project';
    try {
      toast.info('جاري الرفع إلى GitHub...');
      const result = await githubPushMutation.mutateAsync({
        repoName,
        files: project.files.map((f) => ({ path: f.name, content: f.content })),
        description: `Generated by HAYO AI: ${project.description?.slice(0, 100)}`,
      });
      toast.success('تم الرفع إلى GitHub!', { description: result.repoUrl });
      if (result.repoUrl) window.open(result.repoUrl, '_blank');
    } catch (e: any) {
      toast.error('فشل الرفع إلى GitHub', { description: e.message });
    }
  }, [project, githubPushMutation]);

  const handleVercelDeploy = useCallback(async () => {
    if (!project || project.files.length === 0) return;
    const projectName = project.name.slice(0, 30).replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase() || 'hayo-project';
    try {
      toast.info('جاري النشر على Vercel...');
      const result = await vercelDeployMutation.mutateAsync({
        projectName,
        files: project.files.map((f) => ({ path: f.name, content: f.content })),
      });
      toast.success('تم النشر على Vercel!', { description: result.deployUrl });
      if (result.deployUrl) window.open(result.deployUrl, '_blank');
    } catch (e: any) {
      toast.error('فشل النشر على Vercel', { description: e.message });
    }
  }, [project, vercelDeployMutation]);

  const handleOpenByoc = useCallback(() => {
    if (!project) return;
    localStorage.setItem('hayo-byoc-import', JSON.stringify({
      files: project.files.map((f) => ({ name: f.name, content: f.content, language: f.language })),
      importedAt: new Date().toISOString(),
      source: 'completion-screen',
    }));
    navigate('/byoc');
  }, [project, navigate]);

  const handleCopyCode = useCallback((content: string, fileName: string) => {
    navigator.clipboard.writeText(content);
    toast.success(`تم نسخ ${fileName}`);
  }, []);

  // ── Loading State ──────────────────────────────────────────────────
  if (!project && !notFound) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  // ── Not Found ──────────────────────────────────────────────────────
  if (notFound) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center gap-4 p-8 text-center">
        <AlertTriangle className="w-16 h-16 text-yellow-400" />
        <h1 className="text-2xl font-bold">لم يتم العثور على المشروع</h1>
        <p className="text-muted-foreground max-w-md">
          تعذّر تحميل بيانات المشروع. قد يكون الرابط غير صحيح أو انتهت صلاحيته.
        </p>
        <div className="flex gap-3">
          <Button onClick={() => navigate('/agent')} className="bg-primary gap-2">
            <Sparkles className="w-4 h-4" /> مشروع جديد
          </Button>
          <Button variant="outline" onClick={() => navigate('/projects')} className="gap-2">
            <FolderArchive className="w-4 h-4" /> مشاريعي
          </Button>
        </div>
      </div>
    );
  }

  const totalSize = project!.files.reduce((sum, f) => sum + (f.size || f.content.length), 0);
  const activeFile = project!.files[activeFileIdx];

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-emerald-950/10 p-4 md:p-8" dir="rtl">
      <div className="max-w-5xl mx-auto space-y-6">

        {/* ── Top Nav ── */}
        <div className="flex items-center justify-between">
          <Button variant="ghost" size="sm" onClick={() => navigate('/projects')} className="gap-2 text-muted-foreground">
            <ArrowLeft className="w-4 h-4" /> مشاريعي
          </Button>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Link href="/" className="hover:text-foreground transition-colors">
              <Home className="w-4 h-4" />
            </Link>
            <span>/</span>
            <span>الإكمال</span>
          </div>
        </div>

        {/* ── Header ── */}
        <motion.div
          initial={{ opacity: 0, y: -24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center space-y-3"
        >
          <div className="flex justify-center">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: 'spring', damping: 12, stiffness: 200, delay: 0.1 }}
              className="w-20 h-20 rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center shadow-lg shadow-emerald-500/25"
            >
              <CheckCircle2 className="w-10 h-10 text-white" />
            </motion.div>
          </div>
          <h1 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-emerald-400 to-teal-400 bg-clip-text text-transparent">
            تم إنجاز المشروع بنجاح! 🎉
          </h1>
          <p className="text-muted-foreground text-lg max-w-2xl mx-auto">{project!.description || project!.name}</p>
          <div className="flex items-center justify-center gap-4 text-sm text-muted-foreground">
            <span className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" />
              {new Date(project!.createdAt).toLocaleString('ar-SA')}
            </span>
            {project!.category && (
              <span className="px-2 py-0.5 bg-primary/10 text-primary rounded-full text-xs font-medium">
                {project!.category}
              </span>
            )}
          </div>
        </motion.div>

        {/* ── Stats ── */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.4, delay: 0.2 }}
        >
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'عدد الملفات', value: project!.files.length, color: 'text-blue-400', icon: <FileCode className="w-5 h-5" /> },
              { label: 'إجمالي الحجم', value: `${(totalSize / 1024).toFixed(1)} KB`, color: 'text-green-400', icon: <FolderArchive className="w-5 h-5" /> },
              { label: 'الحالة', value: '✅ مكتمل', color: 'text-emerald-400', icon: <CheckCircle2 className="w-5 h-5" /> },
              { label: 'التصنيف', value: project!.category || 'عام', color: 'text-purple-400', icon: <Sparkles className="w-5 h-5" /> },
            ].map((stat, i) => (
              <Card key={i} className="bg-card border-border p-4 text-center space-y-1">
                <div className={`flex justify-center ${stat.color}`}>{stat.icon}</div>
                <div className={`text-xl font-bold ${stat.color}`}>{stat.value}</div>
                <div className="text-xs text-muted-foreground">{stat.label}</div>
              </Card>
            ))}
          </div>
        </motion.div>

        {/* ── Action Buttons ── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.3 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-3"
        >
          <Button
            onClick={handleDownloadZip}
            disabled={isDownloadingZip}
            className="bg-green-600 hover:bg-green-700 gap-2"
          >
            {isDownloadingZip ? <Loader2 className="w-4 h-4 animate-spin" /> : <FolderArchive className="w-4 h-4" />}
            تحميل ZIP
          </Button>
          <Button onClick={handleCopyLink} variant="outline" className="gap-2">
            <Copy className="w-4 h-4" />
            {copied ? 'تم النسخ ✓' : 'نسخ الرابط'}
          </Button>
          <Button onClick={handleShare} variant="outline" className="gap-2">
            <Share2 className="w-4 h-4" />
            مشاركة
          </Button>
          <Button onClick={handleOpenByoc} variant="outline" className="gap-2 text-blue-400 border-blue-400/30 hover:bg-blue-400/10">
            <Code2 className="w-4 h-4" />
            فتح في BYOC
          </Button>
        </motion.div>

        {/* ── Deploy Buttons ── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.35 }}
          className="grid grid-cols-2 gap-3"
        >
          <Button
            onClick={handleGitHubPush}
            disabled={githubPushMutation.isPending}
            variant="outline"
            className="gap-2 text-foreground border-border hover:bg-secondary"
          >
            {githubPushMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Server className="w-4 h-4" />}
            رفع إلى GitHub
          </Button>
          <Button
            onClick={handleVercelDeploy}
            disabled={vercelDeployMutation.isPending}
            variant="outline"
            className="gap-2 text-foreground border-border hover:bg-secondary"
          >
            {vercelDeployMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
            نشر على Vercel
          </Button>
        </motion.div>

        {/* ── Live Preview + Files ── */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.4 }}
        >
          {/* View Toggle Bar */}
          <div className="flex items-center gap-2 mb-3">
            <button
              onClick={() => {
                if (completionView === 'preview') {
                  // Already in preview — force-refresh the iframe
                  setIframeKey(k => k + 1);
                } else {
                  setCompletionView('preview');
                }
              }}
              className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                completionView === 'preview'
                  ? 'bg-emerald-600 text-white shadow-md shadow-emerald-600/20'
                  : 'bg-card border border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              <MonitorPlay className="w-4 h-4" /> معاينة تفاعلية
              {hasWebFiles && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-white/20">LIVE</span>}
            </button>
            <button
              onClick={() => setCompletionView('code')}
              className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                completionView === 'code'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/20'
                  : 'bg-card border border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              <Code2 className="w-4 h-4" /> الملفات والكود
            </button>
          </div>

          {completionView === 'preview' ? (
            /* ── Interactive Preview ── */
            <Card className={`bg-card border-border overflow-hidden ${previewFullscreen ? 'fixed inset-4 z-50' : ''}`}>
              {/* Preview toolbar */}
              <div className="h-9 bg-card border-b border-border flex items-center justify-between px-4 shrink-0">
                <div className="flex items-center gap-2">
                  <div className="flex gap-1.5">
                    <span className="w-3 h-3 rounded-full bg-red-400/80" />
                    <span className="w-3 h-3 rounded-full bg-yellow-400/80" />
                    <span className="w-3 h-3 rounded-full bg-emerald-400/80" />
                  </div>
                  <span className="text-xs text-muted-foreground font-mono">
                    {project!.name.slice(0, 40)} — LIVE PREVIEW
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  {hasWebFiles && (
                    <span className="text-[10px] px-2 py-0.5 bg-emerald-500/15 text-emerald-400 rounded-full border border-emerald-500/20 mr-2">
                      ✓ HTML rendered
                    </span>
                  )}
                  <Button
                    variant="ghost" size="sm"
                    className="h-6 w-6 p-0"
                    onClick={() => setPreviewFullscreen(v => !v)}
                  >
                    {previewFullscreen ? <Minimize2 className="w-3 h-3" /> : <Maximize2 className="w-3 h-3" />}
                  </Button>
                </div>
              </div>
              {/* iframe */}
              <div className={previewFullscreen ? 'h-[calc(100%-36px)]' : 'h-[520px]'}>
                {!hasWebFiles && (
                  <div className="w-full h-full flex flex-col items-center justify-center gap-3 bg-muted/30 text-muted-foreground text-center p-6">
                    <FileCode className="w-10 h-10 opacity-40" />
                    <p className="text-sm">هذا المشروع لا يحتوي على ملفات HTML قابلة للعرض مباشرة</p>
                    <p className="text-xs opacity-60">المشاريع من نوع Python, Node.js وما شابهها تحتاج لبيئة تشغيل</p>
                    <button
                      onClick={() => setCompletionView('code')}
                      className="mt-2 px-4 py-2 rounded-lg text-xs bg-indigo-600 text-white hover:bg-indigo-500 transition-colors"
                    >عرض الكود والملفات</button>
                  </div>
                )}
                {hasWebFiles && (
                  <iframe
                    key={iframeKey}
                    srcDoc={previewHtml}
                    sandbox="allow-scripts allow-modals allow-forms allow-popups allow-downloads"
                    className="w-full h-full border-0 bg-white"
                    title="Live Preview"
                  />
                )}
              </div>
            </Card>
          ) : (
            /* ── Code Viewer ── */
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Files List */}
              <Card className="bg-card border-border p-4 md:col-span-1">
                <h2 className="text-sm font-semibold text-muted-foreground mb-3 flex items-center gap-2">
                  <FileCode className="w-4 h-4" /> الملفات المُنشأة ({project!.files.length})
                </h2>
                <div className="space-y-1 max-h-[460px] overflow-y-auto">
                  {project!.files.map((file, idx) => (
                    <motion.button
                      key={idx}
                      initial={{ opacity: 0, x: 8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.04 * idx }}
                      onClick={() => setActiveFileIdx(idx)}
                      className={`w-full flex items-center justify-between p-2.5 rounded-lg transition text-right ${
                        activeFileIdx === idx
                          ? 'bg-primary/20 border border-primary/30 text-primary'
                          : 'hover:bg-muted/50 text-foreground'
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <Code2 className="w-3.5 h-3.5 shrink-0 text-blue-400" />
                        <div className="min-w-0">
                          <div className="text-xs font-mono truncate">{file.name}</div>
                          <div className="text-[10px] text-muted-foreground">{file.language || 'code'}</div>
                        </div>
                      </div>
                      <div className="text-[10px] text-muted-foreground shrink-0 mr-1">
                        {((file.size || file.content.length) / 1024).toFixed(1)}KB
                      </div>
                    </motion.button>
                  ))}
                </div>
              </Card>

              {/* Code Content */}
              <Card className="bg-card border-border p-4 md:col-span-2">
                {activeFile ? (
                  <>
                    <div className="flex items-center justify-between mb-3">
                      <h2 className="text-sm font-semibold text-muted-foreground flex items-center gap-2">
                        <Eye className="w-4 h-4" /> {activeFile.name}
                      </h2>
                      <Button
                        variant="ghost" size="sm"
                        className="h-7 text-xs gap-1"
                        onClick={() => handleCopyCode(activeFile.content, activeFile.name)}
                      >
                        <Copy className="w-3 h-3" /> نسخ
                      </Button>
                    </div>
                    <pre className="bg-black/40 rounded-lg p-4 text-xs font-mono text-green-400 overflow-auto max-h-[420px] text-left">
                      {activeFile.content.slice(0, 4000)}{activeFile.content.length > 4000 ? '\n\n... (مقتطع)' : ''}
                    </pre>
                  </>
                ) : (
                  <div className="flex items-center justify-center h-40 text-muted-foreground text-sm">
                    اختر ملفاً لعرض محتواه
                  </div>
                )}
              </Card>
            </div>
          )}
        </motion.div>

        {/* ── Bottom Navigation ── */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.5 }}
          className="flex flex-col sm:flex-row gap-3 justify-center pt-4 pb-8"
        >
          <Button
            onClick={() => navigate('/agent')}
            className="bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-700 hover:to-violet-700 gap-2 px-8"
          >
            <Sparkles className="w-4 h-4" /> مشروع جديد
          </Button>
          <Button
            onClick={() => navigate('/projects')}
            variant="outline"
            className="gap-2 px-8"
          >
            <FolderArchive className="w-4 h-4" /> عرض كل المشاريع
          </Button>
        </motion.div>
      </div>
    </div>
  );
}
