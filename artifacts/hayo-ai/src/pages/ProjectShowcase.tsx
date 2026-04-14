/**
 * Project Showcase - عرض المشاريع المُنشأة
 * يقرأ المشاريع الحقيقية من localStorage (hayo-projects)
 */
import { useState, useEffect, useMemo } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useTranslation } from "react-i18next";
import { Link } from "wouter";
import {
  Eye, Download, Trash2, Clock, Code2, Copy, CheckCircle2,
  FileCode, FolderArchive, Home, Sparkles, Search, ArrowLeft,
} from "lucide-react";
import { toast } from "sonner";
import JSZip from "jszip";

interface ProjectFile {
  name: string;
  content: string;
}

interface SavedProject {
  id: string;
  name: string;
  description: string;
  files: ProjectFile[];
  createdAt: string;
  category: string;
  model: string;
}

export default function ProjectShowcase() {
  const { t } = useTranslation();
  const [projects, setProjects] = useState<SavedProject[]>([]);
  const [selectedProject, setSelectedProject] = useState<SavedProject | null>(null);
  const [selectedFileIdx, setSelectedFileIdx] = useState(0);
  const [copied, setCopied] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // Load projects from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem("hayo-projects");
      if (stored) {
        const parsed = JSON.parse(stored) as SavedProject[];
        parsed.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        setProjects(parsed);
      }
    } catch (err) {
      console.error("Failed to load projects:", err);
    }
  }, []);

  const filtered = useMemo(() => {
    if (!searchQuery.trim()) return projects;
    const q = searchQuery.toLowerCase();
    return projects.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.category.toLowerCase().includes(q)
    );
  }, [projects, searchQuery]);

  const handleDeleteProject = (id: string) => {
    const updated = projects.filter((p) => p.id !== id);
    setProjects(updated);
    localStorage.setItem("hayo-projects", JSON.stringify(updated));
    if (selectedProject?.id === id) setSelectedProject(null);
    toast.success(t("common.deleted"));
  };

  const handleCopyCode = (content: string) => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    toast.success(t("common.copied"));
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadFile = (file: ProjectFile) => {
    const blob = new Blob([file.content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = file.name;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`${t("common.download")} ${file.name}`);
  };

  const handleDownloadZip = async (project: SavedProject) => {
    try {
      const zip = new JSZip();
      project.files.forEach((f) => zip.file(f.name, f.content));
      const blob = await zip.generateAsync({ type: "blob" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${project.name.replace(/\s+/g, "-")}.zip`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`ZIP ${t("common.download")}`);
    } catch {
      toast.error(t("common.error"));
    }
  };

  const getFileExtColor = (name: string) => {
    const ext = name.split(".").pop()?.toLowerCase() || "";
    const colors: Record<string, string> = {
      html: "text-orange-400", css: "text-blue-400", js: "text-yellow-400",
      ts: "text-blue-500", tsx: "text-cyan-400", jsx: "text-cyan-300",
      py: "text-green-400", json: "text-amber-400", md: "text-gray-400",
      txt: "text-gray-400", sh: "text-emerald-400", sql: "text-red-400",
    };
    return colors[ext] || "text-gray-400";
  };

  const formatDate = (dateStr: string) => {
    try {
      return new Date(dateStr).toLocaleDateString(undefined, {
        year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
      });
    } catch {
      return dateStr;
    }
  };

  // ─── Project Detail View ─────────────────────────────────────────
  if (selectedProject) {
    const file = selectedProject.files[selectedFileIdx];
    return (
      <div className="h-screen bg-background text-foreground flex flex-col overflow-hidden">
        <header className="h-11 bg-card border-b border-border flex items-center justify-between px-3 shrink-0">
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" className="h-7 px-2 text-xs gap-1" onClick={() => setSelectedProject(null)}>
              <ArrowLeft className="w-3.5 h-3.5" /> {t("common.back")}
            </Button>
            <div className="w-px h-4 bg-border" />
            <span className="text-xs font-bold text-primary">{selectedProject.name}</span>
            <span className="text-[10px] text-muted-foreground">({selectedProject.files.length} {t("common.files")})</span>
          </div>
          <div className="flex items-center gap-1">
            <Button variant="outline" size="sm" className="h-7 px-2 text-xs gap-1" onClick={() => handleDownloadZip(selectedProject)}>
              <FolderArchive className="w-3.5 h-3.5" /> ZIP
            </Button>
            <Link href="/preview">
              <Button variant="outline" size="sm" className="h-7 px-2 text-xs gap-1 text-blue-400 border-blue-400/30">
                <Eye className="w-3.5 h-3.5" /> {t("codeAgent.preview")}
              </Button>
            </Link>
          </div>
        </header>

        <div className="flex-1 flex overflow-hidden">
          <div className="w-48 bg-card/50 border-r border-border overflow-y-auto shrink-0">
            <div className="p-2 text-[10px] font-bold text-muted-foreground uppercase tracking-wider">{t("common.files")}</div>
            {selectedProject.files.map((f, i) => (
              <button
                key={i}
                onClick={() => setSelectedFileIdx(i)}
                className={`w-full text-left px-3 py-2 text-xs flex items-center gap-2 transition-colors ${
                  i === selectedFileIdx ? "bg-primary/10 text-primary border-r-2 border-primary" : "text-muted-foreground hover:bg-secondary/50"
                }`}
              >
                <FileCode className={`w-3.5 h-3.5 shrink-0 ${getFileExtColor(f.name)}`} />
                <span className="truncate font-mono">{f.name}</span>
              </button>
            ))}
          </div>

          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="h-8 bg-card/30 border-b border-border flex items-center justify-between px-3 shrink-0">
              <span className="text-xs font-mono text-muted-foreground">{file?.name}</span>
              <div className="flex items-center gap-1">
                <Button variant="ghost" size="sm" className="h-6 px-2 text-[10px] gap-1" onClick={() => file && handleCopyCode(file.content)}>
                  {copied ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {t("common.copy")}
                </Button>
                <Button variant="ghost" size="sm" className="h-6 px-2 text-[10px] gap-1" onClick={() => file && handleDownloadFile(file)}>
                  <Download className="w-3 h-3" /> {t("common.download")}
                </Button>
              </div>
            </div>
            <div className="flex-1 overflow-auto">
              <pre className="p-4 text-xs font-mono leading-relaxed whitespace-pre-wrap break-words">
                <code>{file?.content || ""}</code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ─── Projects List ───────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="max-w-6xl mx-auto p-6 space-y-6">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">
                <Home className="w-4 h-4" />
              </Link>
              <span className="text-muted-foreground">/</span>
              <span className="text-sm font-medium">{t("nav.projects")}</span>
            </div>
            <h1 className="text-2xl font-bold">{t("nav.projects")}</h1>
            <p className="text-muted-foreground text-sm mt-1">
              {projects.length > 0
                ? `${projects.length} ${t("preview.projectCount")}`
                : t("preview.noProjects")}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-4 h-4 absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t("common.search")}
                className="bg-card border border-border rounded-lg pr-10 pl-4 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary w-56"
              />
            </div>
            <Link href="/agent">
              <Button className="gap-2">
                <Sparkles className="w-4 h-4" /> {t("codeAgent.newMission")}
              </Button>
            </Link>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="text-center py-20">
            <Code2 className="w-16 h-16 mx-auto text-muted-foreground/30 mb-4" />
            <h2 className="text-xl font-bold text-muted-foreground mb-2">{t("preview.noProjects")}</h2>
            <p className="text-muted-foreground text-sm mb-6">{t("preview.noProjectsDesc")}</p>
            <Link href="/agent">
              <Button className="gap-2">
                <Sparkles className="w-4 h-4" /> {t("codeAgent.newMission")}
              </Button>
            </Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filtered.map((project) => (
              <Card
                key={project.id}
                className="bg-card/50 border-border hover:border-primary/30 transition-all cursor-pointer group"
                onClick={() => { setSelectedProject(project); setSelectedFileIdx(0); }}
              >
                <CardContent className="p-5 space-y-3">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <h3 className="font-bold text-sm truncate group-hover:text-primary transition-colors">{project.name}</h3>
                      <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{project.description}</p>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20 shrink-0 ml-2">
                      {project.category}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                    <span className="flex items-center gap-1"><FileCode className="w-3 h-3" /> {project.files.length} {t("common.files")}</span>
                    <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {formatDate(project.createdAt)}</span>
                  </div>

                  <div className="flex flex-wrap gap-1">
                    {project.files.slice(0, 4).map((f, i) => (
                      <span key={i} className={`text-[10px] font-mono px-1.5 py-0.5 rounded bg-secondary/50 ${getFileExtColor(f.name)}`}>
                        {f.name}
                      </span>
                    ))}
                    {project.files.length > 4 && (
                      <span className="text-[10px] text-muted-foreground px-1.5 py-0.5">+{project.files.length - 4}</span>
                    )}
                  </div>

                  <div className="flex items-center gap-1 pt-1" onClick={(e) => e.stopPropagation()}>
                    <Button variant="outline" size="sm" className="h-7 px-2 text-[10px] gap-1 flex-1" onClick={() => { setSelectedProject(project); setSelectedFileIdx(0); }}>
                      <Eye className="w-3 h-3" /> {t("common.view")}
                    </Button>
                    <Button variant="outline" size="sm" className="h-7 px-2 text-[10px] gap-1 flex-1" onClick={() => handleDownloadZip(project)}>
                      <Download className="w-3 h-3" /> ZIP
                    </Button>
                    <Button variant="outline" size="sm" className="h-7 px-2 text-[10px] gap-1 text-red-400 border-red-400/20 hover:bg-red-400/10"
                      onClick={() => { if (confirm(t("common.confirmDelete"))) handleDeleteProject(project.id); }}>
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
