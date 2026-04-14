/**
 * Project Preview - شاشة عرض المشروع
 * Live Preview for generated projects from CodeAgent
 * Reads from localStorage "hayo-projects" key
 */

import { useState, useEffect, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import Editor from "@monaco-editor/react";
import { toast } from "sonner";
import {
  Download, Copy, Eye, Code, FileText, Share2, Trash2, Loader2,
  CheckCircle2, Globe, Maximize2, Minimize2, Home, Terminal,
  MessageSquare, FolderArchive, Lock, ArrowLeft, Play, ExternalLink,
  FileCode, Clock, Tag, RefreshCw,
} from "lucide-react";

const HAYO_LOGO = import.meta.env.VITE_APP_LOGO || "";

interface ProjectFile {
  name: string;
  content: string;
  language: string;
  size: number;
}

interface Project {
  id: string;
  name: string;
  description: string;
  files: ProjectFile[];
  createdAt: string;
  status: "completed" | "processing" | "failed";
  category?: string;
}

function detectLanguage(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  const map: Record<string, string> = {
    js: "javascript", jsx: "javascript", ts: "typescript", tsx: "typescript",
    py: "python", html: "html", css: "css", json: "json", md: "markdown",
    sql: "sql", sh: "shell", yml: "yaml", xml: "xml", java: "java",
    cpp: "cpp", c: "c", rb: "ruby", php: "php", go: "go", rs: "rust",
  };
  return map[ext] || "plaintext";
}

function formatDate(dateStr: string): string {
  try {
    const d = new Date(dateStr);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch { return dateStr; }
}

function buildLivePreviewHtml(files: ProjectFile[]): string {
  const htmlFile = files.find((f) => f.name.endsWith(".html"));
  if (!htmlFile) return "";

  let html = htmlFile.content;

  // Inject CSS files
  const cssFiles = files.filter((f) => f.name.endsWith(".css"));
  for (const css of cssFiles) {
    const linkTag = `<link rel="stylesheet" href="${css.name}">`;
    const styleTag = `<style>/* ${css.name} */\n${css.content}\n</style>`;
    if (html.includes(linkTag)) {
      html = html.replace(linkTag, styleTag);
    } else if (html.includes("</head>")) {
      html = html.replace("</head>", `${styleTag}\n</head>`);
    } else {
      html = `${styleTag}\n${html}`;
    }
  }

  // Inject JS files
  const jsFiles = files.filter((f) => f.name.endsWith(".js") || f.name.endsWith(".jsx"));
  for (const js of jsFiles) {
    const scriptSrc = `<script src="${js.name}"></script>`;
    const scriptTag = `<script>/* ${js.name} */\n${js.content}\n</script>`;
    if (html.includes(scriptSrc)) {
      html = html.replace(scriptSrc, scriptTag);
    } else if (html.includes("</body>")) {
      html = html.replace("</body>", `${scriptTag}\n</body>`);
    } else {
      html = `${html}\n${scriptTag}`;
    }
  }

  return html;
}

export default function ProjectPreview() {
  const { isAuthenticated, loading: authLoading } = useAuth();
  const { t } = useTranslation();
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [selectedFile, setSelectedFile] = useState<ProjectFile | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [previewMode, setPreviewMode] = useState<"code" | "preview">("code");

  // Load projects from localStorage
  useEffect(() => {
    loadProjects();
  }, []);

  const loadProjects = () => {
    try {
      // Try new key first, then fallback to old key
      const stored = localStorage.getItem("hayo-projects") || localStorage.getItem("projects");
      if (stored) {
        const parsed: Project[] = JSON.parse(stored);
        setProjects(parsed);
        if (parsed.length > 0 && !selectedProject) {
          setSelectedProject(parsed[0]);
          setSelectedFile(parsed[0].files[0] || null);
        }
      }
    } catch (e) {
      console.error("Failed to load projects:", e);
    }
  };

  const hasHtmlFile = useMemo(() => {
    if (!selectedProject) return false;
    return selectedProject.files.some((f) => f.name.endsWith(".html"));
  }, [selectedProject]);

  const livePreviewHtml = useMemo(() => {
    if (!selectedProject || !hasHtmlFile) return "";
    return buildLivePreviewHtml(selectedProject.files);
  }, [selectedProject, hasHtmlFile]);

  const handleDownloadFile = () => {
    if (!selectedFile) return;
    const blob = new Blob([selectedFile.content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = selectedFile.name; a.click();
    URL.revokeObjectURL(url);
    toast.success(`${t("preview.download")} ${selectedFile.name}`);
  };

  const handleCopyCode = () => {
    if (!selectedFile) return;
    navigator.clipboard.writeText(selectedFile.content);
    toast.success(t("preview.copy"));
  };

  const handleDownloadZip = async () => {
    if (!selectedProject) return;
    try {
      const JSZip = (await import("jszip")).default;
      const zip = new JSZip();
      selectedProject.files.forEach((f) => zip.file(f.name, f.content));
      const blob = await zip.generateAsync({ type: "blob" });
      const { saveAs } = await import("file-saver");
      saveAs(blob, `${selectedProject.name.replace(/\s+/g, "-")}.zip`);
      toast.success("ZIP " + t("preview.download"));
    } catch { toast.error(t("common.error")); }
  };

  const handleDeleteProject = (projectId: string) => {
    const updated = projects.filter((p) => p.id !== projectId);
    setProjects(updated);
    localStorage.setItem("hayo-projects", JSON.stringify(updated));
    if (selectedProject?.id === projectId) {
      setSelectedProject(updated[0] || null);
      setSelectedFile(updated[0]?.files[0] || null);
    }
    toast.success(t("preview.deleteProject"));
  };

  const handleShareProject = () => {
    if (!selectedProject) return;
    const allCode = selectedProject.files.map((f) => `// === ${f.name} ===\n${f.content}`).join("\n\n");
    navigator.clipboard.writeText(allCode);
    toast.success(t("preview.share"));
  };

  if (authLoading) {
    return <div className="min-h-screen bg-background flex items-center justify-center"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <div className="bg-card border border-border rounded-2xl p-8 max-w-md w-full text-center space-y-4">
          <Lock className="w-12 h-12 text-primary mx-auto" />
          <h2 className="text-xl font-heading font-bold">{t("common.loginRequired")}</h2>
          <p className="text-muted-foreground text-sm">{t("common.loginDesc")}</p>
          <Button asChild className="w-full"><a href={getLoginUrl()}>{t("common.login")}</a></Button>
        </div>
      </div>
    );
  }

  return (
    <div className={`${isFullscreen ? "fixed inset-0 z-50" : "min-h-screen"} bg-background text-foreground`}>
      <div className="flex h-screen flex-col">
        {/* Header */}
        {!isFullscreen && (
          <header className="h-12 bg-card/80 backdrop-blur-xl border-b border-border flex items-center justify-between px-4 shrink-0">
            <div className="flex items-center gap-3">
              <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">
                <Home className="w-4 h-4" />
              </Link>
              <div className="w-px h-5 bg-border" />
              {HAYO_LOGO && <img src={HAYO_LOGO} alt="HAYO" className="w-5 h-5 rounded" />}
              <h1 className="font-heading font-bold text-sm flex items-center gap-2">
                <Eye className="w-4 h-4 text-primary" /> {t("preview.title")}
              </h1>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="sm" className="h-7 text-xs gap-1" onClick={loadProjects}>
                <RefreshCw className="w-3 h-3" /> {t("common.refresh") || "Refresh"}
              </Button>
              <LanguageSwitcher />
              <Link href="/agent">
                <Button variant="outline" size="sm" className="h-7 text-xs gap-1">
                  <Terminal className="w-3 h-3" /> {t("nav.agent")}
                </Button>
              </Link>
              <Link href="/chat">
                <Button variant="outline" size="sm" className="h-7 text-xs gap-1">
                  <MessageSquare className="w-3 h-3" /> {t("nav.chat")}
                </Button>
              </Link>
            </div>
          </header>
        )}

        <div className="flex-1 flex overflow-hidden">
          {/* Left Sidebar - Projects List */}
          {!isFullscreen && (
            <div className="w-64 bg-card border-r border-border flex flex-col shrink-0 overflow-hidden">
              <div className="p-3 border-b border-border">
                <h2 className="font-heading font-bold text-xs text-muted-foreground uppercase tracking-wider">
                  {t("preview.projectCount")} ({projects.length})
                </h2>
              </div>

              <div className="flex-1 overflow-y-auto">
                {projects.length === 0 ? (
                  <div className="text-center py-12 px-4 space-y-3">
                    <Globe className="w-10 h-10 mx-auto text-muted-foreground/30" />
                    <p className="text-sm font-medium text-muted-foreground">{t("preview.noProjects")}</p>
                    <p className="text-xs text-muted-foreground/60">{t("preview.noProjectsDesc")}</p>
                    <Link href="/agent">
                      <Button size="sm" className="mt-2 gap-1">
                        <Terminal className="w-3 h-3" /> {t("nav.agent")}
                      </Button>
                    </Link>
                  </div>
                ) : (
                  <div className="p-2 space-y-1">
                    {projects.map((project) => (
                      <button
                        key={project.id}
                        onClick={() => {
                          setSelectedProject(project);
                          setSelectedFile(project.files[0] || null);
                          setPreviewMode("code");
                        }}
                        className={`w-full text-left p-3 rounded-lg transition-all ${
                          selectedProject?.id === project.id
                            ? "bg-primary/10 border border-primary/30 ring-1 ring-primary/20"
                            : "hover:bg-secondary/50 border border-transparent"
                        }`}
                      >
                        <div className="flex items-start gap-2">
                          <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                            selectedProject?.id === project.id ? "bg-primary/20 text-primary" : "bg-secondary text-muted-foreground"
                          }`}>
                            <FolderArchive className="w-4 h-4" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className="font-medium text-xs truncate text-foreground">{project.name}</p>
                            <div className="flex items-center gap-2 mt-1">
                              <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                                <FileCode className="w-2.5 h-2.5" /> {project.files.length}
                              </span>
                              {project.category && (
                                <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                                  <Tag className="w-2.5 h-2.5" /> {project.category}
                                </span>
                              )}
                            </div>
                            <span className="text-[10px] text-muted-foreground/60 flex items-center gap-0.5 mt-0.5">
                              <Clock className="w-2.5 h-2.5" /> {formatDate(project.createdAt)}
                            </span>
                          </div>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Main Content */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {selectedProject ? (
              <>
                {/* File Tabs */}
                <div className="h-10 bg-card/50 border-b border-border flex items-center px-3 gap-1 overflow-x-auto shrink-0">
                  {selectedProject.files.map((file, idx) => (
                    <button
                      key={idx}
                      onClick={() => { setSelectedFile(file); setPreviewMode("code"); }}
                      className={`px-3 py-1.5 text-xs rounded-t flex items-center gap-1.5 whitespace-nowrap transition-colors ${
                        selectedFile?.name === file.name && previewMode === "code"
                          ? "bg-background text-foreground border-t-2 border-primary"
                          : "text-muted-foreground hover:text-foreground hover:bg-secondary/30"
                      }`}
                    >
                      <FileText className="w-3 h-3" />
                      {file.name}
                    </button>
                  ))}

                  {/* Live Preview Tab */}
                  {hasHtmlFile && (
                    <>
                      <div className="w-px h-5 bg-border mx-1" />
                      <button
                        onClick={() => setPreviewMode("preview")}
                        className={`px-3 py-1.5 text-xs rounded-t flex items-center gap-1.5 whitespace-nowrap transition-colors ${
                          previewMode === "preview"
                            ? "bg-emerald-500/10 text-emerald-400 border-t-2 border-emerald-500"
                            : "text-muted-foreground hover:text-emerald-400 hover:bg-emerald-500/5"
                        }`}
                      >
                        <Play className="w-3 h-3" />
                        Live Preview
                      </button>
                    </>
                  )}
                </div>

                {/* Content Area */}
                <div className="flex-1 overflow-hidden">
                  {previewMode === "preview" && hasHtmlFile ? (
                    <div className="w-full h-full relative bg-white">
                      <iframe
                        srcDoc={livePreviewHtml}
                        className="w-full h-full border-0"
                        title="Live Preview"
                        sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
                      />
                      {/* Fullscreen toggle overlay */}
                      <button
                        onClick={() => setIsFullscreen(!isFullscreen)}
                        className="absolute top-2 right-2 bg-black/60 text-white p-1.5 rounded-lg hover:bg-black/80 transition-colors"
                      >
                        {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                      </button>
                    </div>
                  ) : (
                    <div className="w-full h-full">
                      <Editor
                        height="100%"
                        language={selectedFile?.language || "plaintext"}
                        value={selectedFile?.content || ""}
                        theme="vs-dark"
                        options={{
                          readOnly: true,
                          minimap: { enabled: true },
                          fontSize: 13,
                          lineNumbers: "on",
                          scrollBeyondLastLine: false,
                          automaticLayout: true,
                          wordWrap: "on",
                          padding: { top: 12 },
                        }}
                      />
                    </div>
                  )}
                </div>

                {/* Bottom Actions */}
                <div className="h-11 bg-card border-t border-border flex items-center justify-between px-4 shrink-0">
                  <div className="flex items-center gap-3">
                    {selectedFile && previewMode === "code" && (
                      <span className="text-[10px] text-muted-foreground bg-secondary/50 px-2 py-0.5 rounded font-mono">
                        {selectedFile.name} &middot; {(selectedFile.size / 1024).toFixed(1)} KB &middot; {selectedFile.language}
                      </span>
                    )}
                    {previewMode === "preview" && (
                      <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> Live Preview
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1">
                    <Button size="sm" variant="ghost" onClick={handleCopyCode} className="gap-1 h-7 text-xs px-2">
                      <Copy className="w-3 h-3" /> {t("preview.copy")}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={handleDownloadFile} className="gap-1 h-7 text-xs px-2">
                      <Download className="w-3 h-3" /> {t("preview.download")}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={handleDownloadZip} className="gap-1 h-7 text-xs px-2 text-emerald-400">
                      <FolderArchive className="w-3 h-3" /> ZIP
                    </Button>
                    <Button size="sm" variant="ghost" onClick={handleShareProject} className="gap-1 h-7 text-xs px-2">
                      <Share2 className="w-3 h-3" /> {t("preview.share")}
                    </Button>
                    <div className="w-px h-5 bg-border mx-1" />
                    <Button size="sm" variant="ghost" onClick={() => setIsFullscreen(!isFullscreen)} className="h-7 px-2">
                      {isFullscreen ? <Minimize2 className="w-3 h-3" /> : <Maximize2 className="w-3 h-3" />}
                    </Button>
                    <Button
                      size="sm" variant="ghost"
                      onClick={() => handleDeleteProject(selectedProject.id)}
                      className="h-7 px-2 text-destructive hover:text-destructive"
                    >
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center">
                <div className="text-center space-y-4">
                  <div className="w-20 h-20 mx-auto bg-secondary/30 rounded-2xl flex items-center justify-center">
                    <Globe className="w-10 h-10 text-muted-foreground/30" />
                  </div>
                  <div>
                    <p className="text-lg font-heading font-bold text-muted-foreground">{t("preview.noProjects")}</p>
                    <p className="text-sm text-muted-foreground/60 mt-1">{t("preview.noProjectsDesc")}</p>
                  </div>
                  <Link href="/agent">
                    <Button className="gap-2 mt-2">
                      <Terminal className="w-4 h-4" /> {t("nav.agent")}
                    </Button>
                  </Link>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
