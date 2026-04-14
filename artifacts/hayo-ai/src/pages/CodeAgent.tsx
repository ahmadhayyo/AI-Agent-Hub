/*
 * HAYO AI - Code Agent (Execution Agent) v4.0
 * Features: Live Preview, Vision-to-App, AI Model Selector, Local Agent, i18n
 */

import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { trpc } from "@/lib/trpc";
import { setPendingProject } from "@/lib/projectStore";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import Editor from "@monaco-editor/react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import {
  Play, Copy, Download, Upload, FolderArchive, MessageSquare, FileCode,
  Terminal as TerminalIcon, Loader2, CheckCircle2, Circle, Trash2, Code2,
  Globe, Database, Cpu, Sparkles, Bot, FileText, ChevronRight, ChevronDown,
  Shield, Wifi, Bug, Search, Lock, Smartphone, Wrench, Zap, Server, Brain,
  Home, Eye, PartyPopper, X, Image, MonitorPlay, Maximize2, Minimize2,
  ChevronLeft, RefreshCw, Wand2,
} from "lucide-react";

const HAYO_LOGO = import.meta.env.VITE_APP_LOGO || "";
const API_BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

// ─── Types ───────────────────────────────────────────────────────────
interface GeneratedFile { name: string; content: string; language: string; }
interface ConsoleLog { time: string; message: string; type: "system" | "info" | "success" | "error" | "warning"; }
type WorkflowStep = "idle" | "plan" | "code" | "test" | "edit" | "deliver";
type EditorView = "code" | "preview";

// ─── AI Models ─── IDs must match resolveModel() in llm.ts ──────────
const AI_MODELS = [
  { id: "claude-sonnet", name: "HAYO AI (Claude)", icon: "\u{1F916}", color: "text-indigo-400" },
  { id: "gpt-4o", name: "GPT-4o Mini (OpenAI)", icon: "\u{1F48E}", color: "text-emerald-400" },
  { id: "deepseek-coder", name: "DeepSeek Coder", icon: "\u{1F52C}", color: "text-blue-400" },
  { id: "gemini-pro", name: "Gemini Flash (Google)", icon: "\u2728", color: "text-yellow-400" },
  { id: "groq-llama", name: "Groq Llama 3.3", icon: "\u26A1", color: "text-pink-400" },
  { id: "mistral-large", name: "Mistral Large", icon: "\u{1F30A}", color: "text-cyan-400" },
];

// ─── Helpers ─────────────────────────────────────────────────────────
function detectLanguage(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  const map: Record<string, string> = {
    js: "javascript", jsx: "javascript", ts: "typescript", tsx: "typescript",
    py: "python", html: "html", css: "css", json: "json", md: "markdown",
    sql: "sql", sh: "shell", bash: "shell", yml: "yaml", yaml: "yaml",
    xml: "xml", java: "java", cpp: "cpp", c: "c", rb: "ruby", php: "php",
    go: "go", rs: "rust", swift: "swift", kt: "kotlin", dart: "dart",
    txt: "plaintext", ps1: "powershell", bat: "bat",
  };
  return map[ext] || "plaintext";
}

function getTime(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ─── Build Live Preview HTML ─────────────────────────────────────────
/** Detect if a file's content is renderable HTML regardless of filename */
function looksLikeHtml(content: string): boolean {
  const trimmed = content.trimStart();
  return /^<!doctype\s+html/i.test(trimmed) || /^<html[\s>]/i.test(trimmed);
}

function buildPreviewHtml(files: GeneratedFile[]): string {
  // 1. Find HTML by extension (.html / .htm)
  let htmlFile = files.find(f => /\.html?$/i.test(f.name));

  // 2. If not found by extension, look for a file whose CONTENT starts with HTML
  //    (handles output.txt, index.txt, etc. that contain a full HTML page)
  if (!htmlFile) {
    htmlFile = files.find(f => looksLikeHtml(f.content));
  }

  // 3. Last resort: if any file has an HTML block buried inside (e.g. failed JSON parse)
  //    extract just the HTML portion via regex and unescape JSON string sequences
  if (!htmlFile) {
    for (const f of files) {
      const m = f.content.match(/<!DOCTYPE\s+html[\s\S]*?<\/html>/i);
      if (m) {
        const htmlContent = m[0]
          .replace(/\\n/g, "\n")
          .replace(/\\t/g, "\t")
          .replace(/\\r/g, "\r")
          .replace(/\\"/g, '"')
          .replace(/\\\\/g, "\\");
        htmlFile = { name: "index.html", content: htmlContent, language: "html" };
        break;
      }
    }
  }

  const cssFiles = files.filter(f => f.name.endsWith(".css"));
  const jsFiles  = files.filter(f => /\.[jt]sx?$/.test(f.name) && f !== htmlFile);

  if (htmlFile) {
    let html = htmlFile.content;
    // Inject CSS
    if (cssFiles.length > 0) {
      const cssBlock = cssFiles.map(f => `<style>/* ${f.name} */\n${f.content}</style>`).join("\n");
      html = html.includes("</head>") ? html.replace("</head>", `${cssBlock}\n</head>`) : `${cssBlock}\n${html}`;
    }
    // Inject JS
    if (jsFiles.length > 0) {
      const jsBlock = jsFiles.map(f => `<script>/* ${f.name} */\n${f.content}</script>`).join("\n");
      html = html.includes("</body>") ? html.replace("</body>", `${jsBlock}\n</body>`) : `${html}\n${jsBlock}`;
    }
    return html;
  }

  // 3. CSS + JS only — build a shell
  const css = cssFiles.map(f => f.content).join("\n");
  const js  = jsFiles.map(f => f.content).join("\n");
  if (css || js) {
    return `<!DOCTYPE html><html lang="ar"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${css}</style></head><body><div id="root"></div><script>${js}</script></body></html>`;
  }

  // 4. Non-web project — show all files as a nicely formatted code page
  const allCode = files.map(f =>
    `<h3 style="color:#818cf8;font-family:monospace;margin:16px 0 8px">${escapeHtml(f.name)}</h3>` +
    `<pre style="background:#1e1e2e;padding:16px;border-radius:8px;overflow-x:auto;color:#cdd6f4;font-size:13px;line-height:1.6;white-space:pre-wrap">${escapeHtml(f.content)}</pre>`
  ).join("");
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>body{background:#0f0f23;padding:24px;font-family:system-ui;direction:rtl}</style></head><body>${allCode}</body></html>`;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ─── Component ───────────────────────────────────────────────────────
export default function CodeAgent() {
  const { user, loading: authLoading, isAuthenticated } = useAuth();
  const { t } = useTranslation();
  const [, navigate] = useLocation();

  // State
  const [prompt, setPrompt] = useState("");
  const [files, setFiles] = useState<GeneratedFile[]>([]);
  const [activeFileIndex, setActiveFileIndex] = useState(0);
  const [consoleLogs, setConsoleLogs] = useState<ConsoleLog[]>([
    { time: getTime(), message: "[SYSTEM] HAYO AI Agent v4.0 initialized.", type: "system" },
    { time: getTime(), message: "[SYSTEM] Ready to receive instructions.", type: "info" },
    { time: getTime(), message: "> Awaiting your command ...", type: "warning" },
  ]);
  const [workflowStep, setWorkflowStep] = useState<WorkflowStep>("idle");
  const [isGenerating, setIsGenerating] = useState(false);
  const [isFixing, setIsFixing] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [showCategories, setShowCategories] = useState(false);
  const [fileCount, setFileCount] = useState(0);
  const [showCompletion, setShowCompletion] = useState(false);
  const [fixDescription, setFixDescription] = useState("");
  const [isAiFixing, setIsAiFixing] = useState(false);

  // AI Model Selector
  const [selectedModel, setSelectedModel] = useState("claude-sonnet");
  const [showModelSelector, setShowModelSelector] = useState(false);
  const modelSelectorRef = useRef<HTMLDivElement>(null);

  // Local Agent
  const [localAgentStatus, setLocalAgentStatus] = useState<"disconnected" | "connecting" | "connected">("disconnected");
  const [showLocalAgent, setShowLocalAgent] = useState(false);
  const localAgentRef = useRef<HTMLDivElement>(null);

  // Live Preview
  const [editorView, setEditorView] = useState<EditorView>("code");
  const [previewFullscreen, setPreviewFullscreen] = useState(false);

  // Vision-to-App (Upload UI Design)
  const [uploadingImage, setUploadingImage] = useState(false);
  const imageInputRef = useRef<HTMLInputElement>(null);
  const zipInputRef = useRef<HTMLInputElement>(null);

  const consoleRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Pipeline mode (4 AI models in sequence)
  const [pipelineMode, setPipelineMode] = useState(false);

  // tRPC
  const generateMutation = trpc.agent.generate.useMutation();
  const fixMutation = trpc.agent.fix.useMutation();
  const pipelineMutation = trpc.agent.pipeline.useMutation();
  const fixAllMutation = trpc.agent.fixAll.useMutation();
  const githubPushMutation = trpc.automation.githubPush.useMutation();
  const vercelDeployMutation = trpc.automation.vercelDeploy.useMutation();

  // GitHub Push handler
  const handleGitHubPush = useCallback(async () => {
    if (files.length === 0) return;
    const repoName = prompt.slice(0, 30).replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase() || "hayo-project";
    try {
      addLog("[GITHUB] Pushing to GitHub...", "info");
      const result = await githubPushMutation.mutateAsync({
        repoName,
        files: files.map(f => ({ path: f.name, content: f.content })),
        description: `Generated by HAYO AI: ${prompt.slice(0, 100)}`,
      });
      addLog(`[GITHUB] ${result.message}`, "success");
      toast.success(t("codeAgent.githubPushSuccess"), { description: result.repoUrl });
      if (result.repoUrl) window.open(result.repoUrl, "_blank");
    } catch (e: any) {
      addLog(`[GITHUB] Error: ${e.message}`, "error");
      toast.error(t("codeAgent.githubPushFailed"), { description: e.message });
    }
  }, [files, prompt, githubPushMutation, t]);

  // Vercel Deploy handler
  const handleVercelDeploy = useCallback(async () => {
    if (files.length === 0) return;
    const projectName = prompt.slice(0, 30).replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase() || "hayo-project";
    try {
      addLog("[VERCEL] Deploying to Vercel...", "info");
      const result = await vercelDeployMutation.mutateAsync({
        projectName,
        files: files.map(f => ({ path: f.name, content: f.content })),
      });
      addLog(`[VERCEL] ${result.message}`, "success");
      toast.success(t("codeAgent.vercelDeploySuccess"), { description: result.deployUrl });
      if (result.deployUrl) window.open(result.deployUrl, "_blank");
    } catch (e: any) {
      addLog(`[VERCEL] Error: ${e.message}`, "error");
      toast.error(t("codeAgent.vercelDeployFailed"), { description: e.message });
    }
  }, [files, prompt, vercelDeployMutation, t]);

  // Categories (with i18n)
  const CATEGORIES = useMemo(() => [
    { id: "web", name: "تطوير الويب", nameEn: "WEB DEV", icon: Globe, color: "#6366f1" },
    { id: "scripts", name: "سكربتات", nameEn: "SCRIPTS", icon: FileCode, color: "#22c55e" },
    { id: "data", name: "بيانات", nameEn: "DATA", icon: Database, color: "#3b82f6" },
    { id: "ai", name: "ذكاء اصطناعي", nameEn: "AI & ML", icon: Cpu, color: "#a855f7" },
    { id: "api", name: "واجهات API", nameEn: "API", icon: Code2, color: "#f59e0b" },
    { id: "mobile", name: "تطبيقات", nameEn: "MOBILE", icon: Smartphone, color: "#06b6d4" },
    { id: "defense", name: "أمن دفاعي", nameEn: "DEFENSE", icon: Shield, color: "#10b981" },
    { id: "pentest", name: "اختبار اختراق تعليمي", nameEn: "SECURITY EDU", icon: Bug, color: "#ef4444" },
    { id: "network", name: "شبكات", nameEn: "NETWORK", icon: Wifi, color: "#f97316" },
    { id: "forensics", name: "تحليل جنائي", nameEn: "FORENSICS", icon: Search, color: "#8b5cf6" },
    { id: "general", name: "عام", nameEn: "GENERAL", icon: Sparkles, color: "#ec4899" },
  ], [t]);

  const WORKFLOW_STEPS: { id: WorkflowStep; label: string }[] = pipelineMode
    ? [
        { id: "plan",    label: "Sonnet: تحليل" },
        { id: "code",    label: "Opus: كود" },
        { id: "test",    label: "DeepSeek: مراجعة" },
        { id: "edit",    label: "Gemini: تحسين" },
        { id: "deliver", label: t("codeAgent.deliver") },
      ]
    : [
        { id: "plan",    label: t("codeAgent.plan") },
        { id: "code",    label: t("codeAgent.code") },
        { id: "test",    label: t("codeAgent.test") },
        { id: "edit",    label: t("codeAgent.editStep") },
        { id: "deliver", label: t("codeAgent.deliver") },
      ];

  // Build preview HTML
  const previewHtml = useMemo(() => buildPreviewHtml(files), [files]);

  // Auto-scroll console
  useEffect(() => {
    if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  }, [consoleLogs]);

  const addLog = useCallback((message: string, type: ConsoleLog["type"] = "info") => {
    setConsoleLogs((prev) => [...prev, { time: getTime(), message, type }]);
  }, []);

  const progressWorkflow = useCallback(async (step: WorkflowStep, delay: number) => {
    return new Promise<void>((resolve) => setTimeout(() => { setWorkflowStep(step); resolve(); }, delay));
  }, []);

  // ─── Vision-to-App: Upload UI Design ──────────────────────────────
  const handleUploadDesign = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      toast.error(t("codeAgent.imageOnly"));
      return;
    }
    const imgMax = user?.role === "admin" ? 500 * 1024 * 1024 : 10 * 1024 * 1024;
    if (file.size > imgMax) {
      toast.error(t("codeAgent.imageTooLarge"));
      return;
    }

    setUploadingImage(true);
    addLog(`[VISION] Uploading UI design: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, "system");

    try {
      // Convert image to base64 for the prompt
      const reader = new FileReader();
      const base64 = await new Promise<string>((resolve, reject) => {
        reader.onload = () => resolve(reader.result as string);
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });

      addLog("[VISION] Image loaded. Analyzing UI design with AI...", "info");
      
      // Set prompt with vision instruction
      const visionPrompt = `[VISION-TO-APP] Analyze this UI design image and create an exact replica using React + Tailwind CSS. The image is: ${base64.substring(0, 100)}... (base64 encoded). Create a pixel-perfect implementation with responsive design, proper spacing, colors, and typography matching the uploaded design.`;
      setPrompt(visionPrompt);
      setSelectedCategory("web");
      
      addLog("[VISION] UI design analyzed. Click Execute to generate code.", "success");
      toast.success(t("codeAgent.designUploaded"));
    } catch (err: any) {
      addLog(`[VISION ERROR] ${err.message}`, "error");
      toast.error(t("common.error"));
    }
    
    setUploadingImage(false);
    // Reset file input
    if (imageInputRef.current) imageInputRef.current.value = "";
  }, [addLog, t]);

  // ─── Upload ZIP Project ────────────────────────────────────────────
  const [uploadingZip, setUploadingZip] = useState(false);

  const handleUploadZip = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const name = file.name.toLowerCase();
    const isZip = name.endsWith(".zip");
    const isRar = name.endsWith(".rar");
    if (!isZip && !isRar) {
      toast.error("يرجى رفع ملف ZIP أو RAR فقط");
      return;
    }
    const zipMax = user?.role === "admin" ? 500 * 1024 * 1024 : 50 * 1024 * 1024;
    if (file.size > zipMax) {
      toast.error(user?.role === "admin" ? "الحجم يتجاوز 500MB" : "الحجم يتجاوز 50MB");
      return;
    }

    setUploadingZip(true);
    const fmt = isRar ? "RAR" : "ZIP";
    addLog(`[UPLOAD] Loading ${fmt}: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, "system");

    try {
      let extractedFiles: GeneratedFile[] = [];

      if (isZip) {
        // Client-side ZIP extraction (fast)
        const JSZip = (await import("jszip")).default;
        const zip = await JSZip.loadAsync(await file.arrayBuffer());
        const textExts = ["js","jsx","ts","tsx","py","html","css","json","md","txt",
          "xml","yaml","yml","sh","sql","rb","php","go","rs","java","cpp","c","h",
          "dart","kt","swift","env","toml","gitignore","vue","svelte","astro","cs","lua"];
        for (const [filename, zipEntry] of Object.entries(zip.files)) {
          if ((zipEntry as any).dir) continue;
          if (["node_modules/",".git/","__pycache__/","dist/"].some(d => filename.includes(d))) continue;
          const ext = filename.split(".").pop()?.toLowerCase() || "";
          if (!textExts.includes(ext)) continue;
          try {
            const content = await (zipEntry as any).async("text");
            if (content.length < 500_000) extractedFiles.push({ name: filename, content, language: detectLanguage(filename) });
          } catch {}
        }
      } else {
        // RAR: send to backend for extraction
        addLog("[UPLOAD] Sending RAR to server for extraction...", "info");
        const formData = new FormData();
        formData.append("file", file, file.name);
        const res = await fetch(`${API_BASE}/api/files/extract-archive`, {
          method: "POST",
          credentials: "include",
          body: formData,
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error((err as any).error || `HTTP ${res.status}`);
        }
        const data = await res.json();
        extractedFiles = (data.files as { name: string; content: string }[]).map(f => ({
          name: f.name,
          content: f.content,
          language: detectLanguage(f.name),
        }));
      }

      if (extractedFiles.length === 0) {
        toast.error("لم يتم العثور على ملفات كود في الأرشيف");
        setUploadingZip(false);
        return;
      }

      extractedFiles.sort((a, b) => a.name.localeCompare(b.name));
      setFiles(extractedFiles);
      setFileCount(extractedFiles.length);
      setActiveFileIndex(0);
      setWorkflowStep("idle");
      setShowCompletion(false);
      setEditorView("code");
      setPrompt(`لدي مشروع مكون من ${extractedFiles.length} ملف مستخرج من ${file.name}، حللهم وصحح الأخطاء وحسّن الكود`);

      addLog(`[UPLOAD] ✅ Extracted ${extractedFiles.length} files from ${file.name}`, "success");
      addLog("[UPLOAD] Files loaded into editor. Describe what to fix or click Execute.", "info");
      toast.success(`تم تحميل ${extractedFiles.length} ملف من ${file.name}`);
    } catch (err: any) {
      addLog(`[UPLOAD ERROR] ${err.message}`, "error");
      toast.error(`فشل استخراج الملفات: ${err.message}`);
    }

    setUploadingZip(false);
    if (zipInputRef.current) zipInputRef.current.value = "";
  }, [addLog, t]);

  // ─── Open in BYOC (Manual Workspace) ──────────────────────────────
  const handleOpenInBYOC = useCallback(() => {
    if (files.length === 0) return;
    try {
      // Save current files to localStorage for BYOC to pick up
      const byocData = {
        files: files.map(f => ({ name: f.name, content: f.content, language: f.language })),
        importedAt: new Date().toISOString(),
        source: "code-agent",
      };
      localStorage.setItem("hayo-byoc-import", JSON.stringify(byocData));
      addLog("[TRANSFER] Code transferred to Manual Workspace (BYOC).", "success");
      toast.success(t("codeAgent.openInBYOC"));
      navigate("/byoc");
    } catch (err: any) {
      toast.error(t("common.error"));
    }
  }, [files, addLog, t, navigate]);

  // ─── Save project & navigate helper ───────────────────────────────
  const saveAndNavigate = useCallback(async (
    resultFiles: { name: string; content: string }[],
    summary: string,
  ) => {
    for (let i = 0; i < resultFiles.length; i++) {
      const file = resultFiles[i];
      await new Promise<void>((r) => setTimeout(r, 250));
      const genFile: GeneratedFile = { name: file.name, content: file.content, language: detectLanguage(file.name) };
      setFiles((prev) => [...prev, genFile]);
      setFileCount((prev) => prev + 1);
      setActiveFileIndex(i);
      addLog(`[FILE] Generated: ${file.name} (${file.content.length} chars)`, "success");
    }
    await progressWorkflow("deliver", 400);
    addLog(`[DELIVER] ${resultFiles.length} file(s) ready.`, "success");
    addLog("[SYSTEM] Mission complete.", "system");
    if (summary) addLog(`[SUMMARY] ${summary}`, "info");

    const projectId = `proj-${Date.now()}`;
    const newProject = {
      id: projectId,
      name: prompt.trim().substring(0, 60),
      description: summary || prompt.trim(),
      files: resultFiles.map((f) => ({
        name: f.name, content: f.content, language: detectLanguage(f.name), size: f.content.length,
      })),
      createdAt: new Date().toISOString(),
      status: "completed" as const,
      category: selectedCategory || "general",
    };

    // 1. In-memory store + persist for history
    setPendingProject(newProject);
    try {
      const existingProjects = JSON.parse(localStorage.getItem("hayo-projects") || "[]");
      existingProjects.unshift(newProject);
      if (existingProjects.length > 50) existingProjects.length = 50;
      localStorage.setItem("hayo-projects", JSON.stringify(existingProjects));
    } catch { /* storage full */ }
    try { sessionStorage.setItem("hayo-current-project", JSON.stringify(newProject)); } catch { /* noop */ }

    // Show the inline result overlay — no navigation needed, works in all environments
    // Default to "preview" only if an HTML file exists; otherwise show "code" view
    const hasHtmlFile = resultFiles.some(f => /\.html?$/i.test(f.name) || looksLikeHtml(f.content));
    setEditorView(hasHtmlFile ? "preview" : "code");
    setShowCompletion(true);
  }, [prompt, selectedCategory, addLog, progressWorkflow, navigate]);

  // ─── Execute Generation ────────────────────────────────────────────
  const handleExecute = useCallback(async () => {
    if (!prompt.trim() || isGenerating) return;
    if (!isAuthenticated) { window.location.href = getLoginUrl(); return; }

    setIsGenerating(true);
    setFiles([]);
    setFileCount(0);
    setActiveFileIndex(0);
    setShowCompletion(false);
    setEditorView("code");
    setWorkflowStep("plan");
    addLog(`[MISSION] "${prompt.trim().substring(0, 100)}..."`, "info");

    try {
      if (pipelineMode) {
        // ── 4-Model Pipeline ──────────────────────────────────────────
        addLog("[PIPELINE] تشغيل خط الإنتاج المتعدد النماذج...", "system");
        addLog("[PHASE 1/4] Claude Sonnet: تحليل الطلب وبناء الخطة...", "info");

        await progressWorkflow("code", 800);
        addLog("[PHASE 2/4] GPT-4o: كتابة الكود الكامل...", "info");

        // Fire the single pipeline mutation (runs all 4 models server-side)
        const pipelinePromise = pipelineMutation.mutateAsync({
          prompt: prompt.trim(),
          category: selectedCategory || "general",
        });

        // Show progress animation while waiting
        const reviewDelay = new Promise<void>((r) => setTimeout(r, 12000));
        await Promise.race([reviewDelay, pipelinePromise.then(() => {})]);
        await progressWorkflow("test", 0);
        addLog("[PHASE 3/4] DeepSeek: مراجعة الكود وإصلاح الأخطاء...", "info");

        const enhanceDelay = new Promise<void>((r) => setTimeout(r, 8000));
        await Promise.race([enhanceDelay, pipelinePromise.then(() => {})]);
        await progressWorkflow("edit", 0);
        addLog("[PHASE 4/4] Gemini: إضافة الملفات الناقصة وإنهاء المشروع...", "info");

        const result = await pipelinePromise;

        if (result.files && result.files.length > 0) {
          await saveAndNavigate(result.files, result.summary);
        } else {
          addLog("[ERROR] لم يتم إنشاء ملفات. حاول بطلب أكثر تفصيلاً.", "error");
          setWorkflowStep("idle");
        }
      } else {
        // ── Single Model Generation ───────────────────────────────────
        const modelInfo = AI_MODELS.find((m) => m.id === selectedModel);
        addLog(`[AGENT] Using model: ${modelInfo?.name || "Default"}`, "system");
        addLog("[AGENT] Analyzing request...", "system");
        addLog("[PLAN] Breaking down task into components...", "info");

        await progressWorkflow("code", 1500);
        addLog("[CODE] Generating code files...", "system");

        const result = await generateMutation.mutateAsync({
          prompt: prompt.trim(),
          category: selectedCategory || "general",
          model: selectedModel,
        });

        if (result.files && result.files.length > 0) {
          await progressWorkflow("test", 600);
          addLog("[TEST] Validating generated code...", "system");
          await new Promise((r) => setTimeout(r, 500));
          addLog("[TEST] Syntax check passed.", "success");
          await progressWorkflow("edit", 400);
          addLog("[EDIT] Optimizing and formatting...", "system");
          await new Promise((r) => setTimeout(r, 400));
          addLog("[EDIT] Code optimized.", "success");
          await saveAndNavigate(result.files, result.summary);
        } else {
          addLog("[ERROR] No files generated. Try a more specific request.", "error");
          setWorkflowStep("idle");
        }
      }
    } catch (error: any) {
      addLog(`[ERROR] ${error.message || "Generation failed"}`, "error");
      setWorkflowStep("idle");
    }

    setIsGenerating(false);
  }, [prompt, isGenerating, isAuthenticated, selectedCategory, selectedModel, pipelineMode,
      addLog, progressWorkflow, generateMutation, pipelineMutation, saveAndNavigate]);

  // ─── AI Fix ────────────────────────────────────────────────────────
  const handleAiFix = useCallback(async () => {
    if (files.length === 0 || isFixing || isGenerating) return;
    const file = files[activeFileIndex];
    if (!file) return;
    setIsFixing(true);
    addLog(`[AI FIX] Analyzing ${file.name}...`, "system");
    try {
      const result = await fixMutation.mutateAsync({ code: file.content, fileName: file.name, category: selectedCategory || "general", model: selectedModel });
      if (result.fixedCode) {
        setFiles((prev) => { const u = [...prev]; u[activeFileIndex] = { ...u[activeFileIndex], content: result.fixedCode }; return u; });
        addLog(`[AI FIX] Fixed ${file.name}!`, "success");
        result.fixes.forEach((f: string) => addLog(`  > ${f}`, "info"));
        toast.success(t("codeAgent.aiFix") + ` ${file.name}`);
      }
    } catch (error: any) {
      addLog(`[AI FIX ERROR] ${error.message}`, "error");
      toast.error(t("common.error"));
    }
    setIsFixing(false);
  }, [files, activeFileIndex, isFixing, isGenerating, selectedCategory, fixMutation, addLog, t]);

  // ─── Fix ALL files in project ──────────────────────────────────────
  const handleFixAll = useCallback(async () => {
    if (files.length === 0 || isFixing || isGenerating) return;
    setIsFixing(true);
    addLog(`[FIX ALL] إصلاح ${files.length} ملف بالذكاء الاصطناعي...`, "system");
    try {
      const result = await fixAllMutation.mutateAsync({
        files: files.map(f => ({ name: f.name, content: f.content })),
        description: fixDescription || undefined,
        model: selectedModel,
      });
      if (result.files?.length > 0) {
        setFiles(result.files.map((f: any) => ({
          name: f.name, content: f.content, language: detectLanguage(f.name),
        })));
        addLog(`[FIX ALL] ✅ تم إصلاح ${result.totalFixes} مشكلة في ${result.files.length} ملف`, "success");
        result.fixes.forEach((f: string) => addLog(`  🔧 ${f}`, "info"));
        toast.success(`✅ تم إصلاح ${result.totalFixes} مشكلة`);
      }
    } catch (error: any) {
      addLog(`[FIX ALL ERROR] ${error.message}`, "error");
      toast.error(`فشل: ${error.message}`);
    }
    setIsFixing(false);
  }, [files, isFixing, isGenerating, fixDescription, selectedModel, fixAllMutation, addLog]);

  // ─── AI Fix from Result Overlay ────────────────────────────────────
  const handleOverlayFix = useCallback(async () => {
    if (!fixDescription.trim() || isAiFixing || files.length === 0) return;
    setIsAiFixing(true);
    addLog(`[FIX] Fixing with description: ${fixDescription}`, "info");
    try {
      // Fix the main HTML file first, or the active file
      const targetIdx = files.findIndex(f => /\.html?$/i.test(f.name));
      const idx = targetIdx >= 0 ? targetIdx : activeFileIndex;
      const file = files[idx];
      const result = await fixMutation.mutateAsync({
        code: file.content,
        fileName: file.name,
        category: selectedCategory || "general",
        model: selectedModel,
        userDescription: fixDescription,
      });
      if (result.fixed) {
        const updated = [...files];
        updated[idx] = { ...updated[idx], content: result.fixed };
        setFiles(updated);
        setActiveFileIndex(idx);
        setFixDescription("");
        addLog(`[FIX] Applied fix successfully`, "success");
        toast.success("تم الإصلاح بنجاح");
      }
    } catch {
      toast.error("فشل الإصلاح، حاول مجدداً");
    }
    setIsAiFixing(false);
  }, [fixDescription, isAiFixing, files, activeFileIndex, selectedCategory, selectedModel, fixMutation, addLog, t]);

  // ─── Copy/Download/ZIP ─────────────────────────────────────────────
  const handleCopyAll = useCallback(() => {
    if (files.length === 0) return;
    const allCode = files.map((f) => `// === ${f.name} ===\n${f.content}`).join("\n\n");
    navigator.clipboard.writeText(allCode);
    toast.success(t("codeAgent.copyAll"));
  }, [files, t]);

  const handleDownloadFile = useCallback(() => {
    if (files.length === 0) return;
    const file = files[activeFileIndex];
    const blob = new Blob([file.content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = file.name; a.click();
    URL.revokeObjectURL(url);
    toast.success(t("codeAgent.downloadFile") + ` ${file.name}`);
  }, [files, activeFileIndex, t]);

  const handleDownloadZip = useCallback(async () => {
    if (files.length === 0) return;
    try {
      const JSZip = (await import("jszip")).default;
      const zip = new JSZip();
      files.forEach((f) => zip.file(f.name, f.content));
      const blob = await zip.generateAsync({ type: "blob" });
      const { saveAs } = await import("file-saver");
      saveAs(blob, "hayo-ai-generated.zip");
      toast.success(t("codeAgent.downloadZip"));
    } catch { toast.error(t("common.error")); }
  }, [files, t]);

  const handleClear = useCallback(() => {
    setFiles([]); setFileCount(0); setActiveFileIndex(0); setPrompt(""); setWorkflowStep("idle"); setShowCompletion(false); setEditorView("code");
    setConsoleLogs([{ time: getTime(), message: "[SYSTEM] Agent reset.", type: "system" }, { time: getTime(), message: "> Awaiting your command ...", type: "warning" }]);
  }, []);

  // ─── Local Agent Connection (Real WebSocket) ──────────────────────
  const wsRef = useRef<WebSocket | null>(null);
  const [wsAddress, setWsAddress] = useState("ws://localhost:8765");

  const handleLocalAgentConnect = useCallback(() => {
    if (localAgentStatus === "connected" && wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
      setLocalAgentStatus("disconnected");
      addLog("[LOCAL AGENT] Disconnected.", "warning");
      toast.success(t("codeAgent.disconnectLocal"));
      return;
    }

    setLocalAgentStatus("connecting");
    addLog(`[LOCAL AGENT] Attempting WebSocket connection to ${wsAddress}...`, "system");

    try {
      const ws = new WebSocket(wsAddress);
      const timeout = setTimeout(() => {
        if (ws.readyState !== WebSocket.OPEN) {
          ws.close();
          setLocalAgentStatus("disconnected");
          addLog("[LOCAL AGENT] Connection timed out (5s). Ensure local agent service is running.", "warning");
          toast.error(t("codeAgent.localDisconnected"));
        }
      }, 5000);

      ws.onopen = () => {
        clearTimeout(timeout);
        setLocalAgentStatus("connected");
        wsRef.current = ws;
        addLog("[LOCAL AGENT] Connected successfully!", "success");
        toast.success(t("codeAgent.localConnected"));
        ws.send(JSON.stringify({ type: "handshake", agent: "hayo-ai", version: "4.0" }));
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          addLog(`[LOCAL AGENT] ${data.message || JSON.stringify(data)}`, "info");
        } catch {
          addLog(`[LOCAL AGENT] ${event.data}`, "info");
        }
      };

      ws.onerror = () => {
        clearTimeout(timeout);
        setLocalAgentStatus("disconnected");
        addLog("[LOCAL AGENT] Connection error. Check if the local agent is running.", "error");
        toast.error(t("codeAgent.localDisconnected"));
      };

      ws.onclose = () => {
        clearTimeout(timeout);
        if (localAgentStatus === "connected") {
          setLocalAgentStatus("disconnected");
          addLog("[LOCAL AGENT] Connection closed.", "warning");
        }
        wsRef.current = null;
      };
    } catch (err: any) {
      setLocalAgentStatus("disconnected");
      addLog(`[LOCAL AGENT] Failed: ${err.message}`, "error");
      toast.error(t("codeAgent.localDisconnected"));
    }
  }, [localAgentStatus, wsAddress, addLog, t]);

  // Cleanup WebSocket on unmount
  useEffect(() => {
    return () => { if (wsRef.current) wsRef.current.close(); };
  }, []);

  // Close model selector / local agent panel when clicking outside
  useEffect(() => {
    if (!showModelSelector && !showLocalAgent) return;
    const handler = (e: MouseEvent) => {
      if (showModelSelector && modelSelectorRef.current && !modelSelectorRef.current.contains(e.target as Node)) {
        setShowModelSelector(false);
      }
      if (showLocalAgent && localAgentRef.current && !localAgentRef.current.contains(e.target as Node)) {
        setShowLocalAgent(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showModelSelector, showLocalAgent]);

  const activeFile = files[activeFileIndex] || null;

  const logColor = (type: ConsoleLog["type"]) => {
    switch (type) {
      case "system": return "text-indigo-400";
      case "success": return "text-emerald-400";
      case "error": return "text-red-400";
      case "warning": return "text-amber-400";
      default: return "text-gray-300";
    }
  };

  if (authLoading) {
    return <div className="min-h-screen bg-background flex items-center justify-center"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
  }

  // ─── Project Completion Full-Screen Overlay ───────────────────────
  if (showCompletion && files.length > 0) {
    const completionView = editorView; // reuse editorView: "preview" | "code"

    return (
      <div className="fixed inset-0 z-50 bg-background text-foreground flex flex-col">
        {/* ── TOP BAR ──────────────────────────────────────────────── */}
        <div className="flex items-center gap-2 px-3 py-2 bg-card border-b border-border shrink-0">
          {/* Back */}
          <Button
            variant="ghost"
            size="sm"
            className="gap-1.5 text-sm text-muted-foreground hover:text-foreground"
            onClick={() => setShowCompletion(false)}
          >
            <ChevronLeft className="w-4 h-4" />
            <span className="hidden sm:inline">{t("common.back")}</span>
          </Button>

          {/* Divider */}
          <div className="w-px h-5 bg-border" />

          {/* Project name badge */}
          <div className="flex items-center gap-1.5 min-w-0">
            <PartyPopper className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="font-semibold text-sm truncate max-w-[160px]">
              {prompt.slice(0, 40) || t("codeAgent.completionTitle")}
            </span>
            <span className="text-muted-foreground text-xs shrink-0">
              · {files.length} {t("common.files")}
            </span>
          </div>

          {/* Spacer */}
          <div className="flex-1" />

          {/* Preview / Code toggle */}
          <div className="flex items-center bg-secondary rounded-lg p-0.5 gap-0.5">
            <button
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                completionView === "preview"
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
              onClick={() => setEditorView("preview")}
            >
              <MonitorPlay className="w-3.5 h-3.5" />
              {t("codeAgent.preview")}
            </button>
            <button
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                completionView === "code"
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
              onClick={() => setEditorView("code")}
            >
              <Code2 className="w-3.5 h-3.5" />
              {t("codeAgent.code")}
            </button>
          </div>

          {/* Divider */}
          <div className="w-px h-5 bg-border hidden sm:block" />

          {/* Action buttons */}
          <div className="hidden sm:flex items-center gap-1.5">
            <Button variant="ghost" size="sm" className="gap-1.5 text-xs h-8 px-2.5" onClick={handleDownloadZip}>
              <FolderArchive className="w-3.5 h-3.5 text-emerald-400" /> ZIP
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="gap-1.5 text-xs h-8 px-2.5"
              onClick={handleGitHubPush}
              disabled={githubPushMutation.isPending}
            >
              {githubPushMutation.isPending
                ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                : <Server className="w-3.5 h-3.5" />
              }
              GitHub
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="gap-1.5 text-xs h-8 px-2.5"
              onClick={handleVercelDeploy}
              disabled={vercelDeployMutation.isPending}
            >
              {vercelDeployMutation.isPending
                ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                : <Globe className="w-3.5 h-3.5 text-blue-400" />
              }
              Vercel
            </Button>
          </div>

          {/* New project */}
          <Button
            variant="ghost"
            size="sm"
            className="gap-1.5 text-xs h-8 px-2.5 text-violet-400 hover:text-violet-300"
            onClick={() => { setShowCompletion(false); handleClear(); }}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{t("codeAgent.newMission")}</span>
          </Button>
        </div>

        {/* ── MAIN AREA ─────────────────────────────────────────────── */}
        <div className="flex-1 overflow-hidden">
          {completionView === "preview" ? (
            /* Live Preview — buildPreviewHtml handles HTML, CSS/JS, and non-web files */
            previewHtml ? (
              <iframe
                key={`completion-preview-${files.map(f => f.content.length).join("-")}`}
                srcDoc={previewHtml}
                sandbox="allow-scripts allow-modals allow-forms allow-popups allow-downloads allow-same-origin"
                className="w-full h-full border-0 bg-white"
                title="Live Preview"
              />
            ) : (
              <div className="w-full h-full flex items-center justify-center text-muted-foreground">
                <div className="text-center space-y-3">
                  <FileCode className="w-12 h-12 mx-auto opacity-40" />
                  <p className="text-sm">{t("codeAgent.noHtmlPreview")}</p>
                  <Button variant="outline" size="sm" onClick={() => setEditorView("code")}>
                    <Code2 className="w-4 h-4 mr-2" /> {t("codeAgent.viewCode")}
                  </Button>
                </div>
              </div>
            )
          ) : (
            /* Code View — file tabs + content */
            <div className="h-full flex flex-col">
              {/* File tabs */}
              <div className="flex items-center gap-0.5 px-2 pt-2 pb-0 bg-card border-b border-border overflow-x-auto shrink-0">
                {files.map((f, i) => (
                  <button
                    key={i}
                    onClick={() => setActiveFileIndex(i)}
                    className={`flex items-center gap-1.5 px-3 py-2 rounded-t-md text-xs font-mono transition-all shrink-0 ${
                      activeFileIndex === i
                        ? "bg-background text-foreground border border-b-0 border-border"
                        : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                    }`}
                  >
                    <FileCode className="w-3 h-3" />
                    {f.name}
                  </button>
                ))}
              </div>
              {/* Code content */}
              <div className="flex-1 overflow-auto bg-background">
                <pre className="p-4 text-xs font-mono text-foreground whitespace-pre-wrap leading-relaxed">
                  <code>{files[activeFileIndex]?.content || ""}</code>
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* ── AI FIX BAR ────────────────────────────────────────────── */}
        <div className="shrink-0 border-t border-border bg-card px-3 py-2.5">
          <div className="flex items-center gap-2 max-w-4xl mx-auto">
            <Wand2 className="w-4 h-4 text-violet-400 shrink-0" />
            <input
              type="text"
              value={fixDescription}
              onChange={e => setFixDescription(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleOverlayFix(); } }}
              placeholder={t("codeAgent.aiFixPlaceholder") || "اطلب إصلاحاً أو تحسيناً... (مثال: أصلح الزر الأحمر، غيّر الخط)"}
              className="flex-1 bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-violet-500/50 text-right"
              dir="rtl"
              disabled={isAiFixing}
            />
            <Button
              size="sm"
              className="gap-1.5 bg-violet-600 hover:bg-violet-700 text-white h-9 px-4 shrink-0"
              onClick={handleOverlayFix}
              disabled={isAiFixing || !fixDescription.trim()}
            >
              {isAiFixing
                ? <Loader2 className="w-4 h-4 animate-spin" />
                : <Wand2 className="w-4 h-4" />
              }
              <span className="hidden sm:inline">{isAiFixing ? t("common.loading") : t("codeAgent.fix")}</span>
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 h-9 px-3 text-xs shrink-0"
              onClick={() => { setEditorView(completionView === "preview" ? "code" : "preview"); }}
            >
              {completionView === "preview"
                ? <><Code2 className="w-3.5 h-3.5" /><span className="hidden sm:inline">{t("codeAgent.code")}</span></>
                : <><MonitorPlay className="w-3.5 h-3.5" /><span className="hidden sm:inline">{t("codeAgent.preview")}</span></>
              }
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // ─── Main Layout ───────────────────────────────────────────────────
  return (
    <div className="h-screen bg-background text-foreground flex flex-col overflow-hidden">
      {/* === TOP BAR === */}
      <header className="h-11 bg-card border-b border-border flex items-center justify-between px-3 shrink-0">
        <div className="flex items-center gap-2">
          <Link href="/" className="text-muted-foreground hover:text-primary transition-colors px-1.5 py-1 rounded hover:bg-primary/10">
            <Home className="w-3.5 h-3.5" />
          </Link>
          <div className="w-px h-4 bg-border" />
          <Link href="/chat" className="flex items-center gap-1 text-muted-foreground hover:text-primary transition-colors px-1.5 py-1 rounded hover:bg-primary/10">
            <MessageSquare className="w-3.5 h-3.5" /><span className="text-[10px] font-bold hidden sm:inline">{t("nav.chat")}</span>
          </Link>
          <Link href="/byoc" className="flex items-center gap-1 text-muted-foreground hover:text-primary transition-colors px-1.5 py-1 rounded hover:bg-primary/10">
            <Code2 className="w-3.5 h-3.5" /><span className="text-[10px] font-bold hidden sm:inline">BYOC</span>
          </Link>
          <div className="w-px h-4 bg-border" />
          {HAYO_LOGO && <img src={HAYO_LOGO} alt="HAYO" className="w-5 h-5 rounded" />}
          <span className="font-heading font-bold text-xs">HAYO AI AGENT</span>
          <span className="text-[9px] text-muted-foreground px-1.5 py-0.5 bg-secondary rounded">v4.0</span>
        </div>

        <div className="flex items-center gap-1">
          {/* AI Model Selector Button */}
          <div className="relative" ref={modelSelectorRef}>
            <Button variant="ghost" size="sm" className="text-[10px] gap-1 h-7 px-2" onClick={() => setShowModelSelector(!showModelSelector)}>
              <Brain className="w-3 h-3 text-violet-400" />
              <span className="hidden sm:inline">{AI_MODELS.find((m) => m.id === selectedModel)?.icon} {AI_MODELS.find((m) => m.id === selectedModel)?.name.split(" ")[0]}</span>
            </Button>
            {showModelSelector && (
              <div className="absolute top-full right-0 mt-1 w-72 bg-card border border-border rounded-xl shadow-xl z-50 p-2 space-y-0.5">
                <div className="px-2 py-1 text-[10px] font-bold text-muted-foreground uppercase tracking-wider">{t("codeAgent.aiModel")}</div>
                {AI_MODELS.map((model) => (
                  <button key={model.id} onClick={() => { setSelectedModel(model.id); setShowModelSelector(false); toast.success(`${model.name}`); }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition-colors ${selectedModel === model.id ? "bg-primary/15 text-primary ring-1 ring-primary/30" : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"}`}>
                    <span className="text-lg">{model.icon}</span>
                    <div className="text-right flex-1">
                      <div className={`font-bold ${model.color}`}>{model.name}</div>
                    </div>
                    {selectedModel === model.id && <CheckCircle2 className="w-4 h-4 text-primary shrink-0" />}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Local Agent Button */}
          <div className="relative" ref={localAgentRef}>
            <Button variant="ghost" size="sm" className={`text-[10px] gap-1 h-7 px-2 ${localAgentStatus === "connected" ? "text-emerald-400" : localAgentStatus === "connecting" ? "text-amber-400" : ""}`}
              onClick={() => setShowLocalAgent(!showLocalAgent)}>
              <Server className="w-3 h-3" />
              <span className="hidden sm:inline">{localAgentStatus === "connected" ? t("codeAgent.localConnected") : t("codeAgent.localAgent")}</span>
              {localAgentStatus === "connected" && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />}
            </Button>
            {showLocalAgent && (
              <div className="absolute top-full right-0 mt-1 w-72 bg-card border border-border rounded-xl shadow-xl z-50 p-3 space-y-3">
                <div className="text-xs font-bold">{t("codeAgent.localAgent")}</div>
                <div className="space-y-1">
                  <label className="text-[10px] text-muted-foreground">{t("codeAgent.wsAddress")}</label>
                  <input type="text" value={wsAddress} onChange={(e) => setWsAddress(e.target.value)}
                    placeholder="ws://localhost:8765"
                    className="w-full bg-secondary/50 border border-border rounded-md px-2 py-1.5 text-xs font-mono text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary"
                    disabled={localAgentStatus === "connected"} />
                </div>
                <div className="flex items-center gap-2 text-[10px]">
                  <span className={`w-2 h-2 rounded-full ${localAgentStatus === "connected" ? "bg-emerald-400" : localAgentStatus === "connecting" ? "bg-amber-400 animate-pulse" : "bg-gray-400"}`} />
                  <span>{localAgentStatus === "connected" ? t("codeAgent.localConnected") : localAgentStatus === "connecting" ? t("common.loading") : t("codeAgent.localDisconnected")}</span>
                </div>
                <Button size="sm" className={`w-full text-xs gap-1 ${localAgentStatus === "connected" ? "bg-red-600 hover:bg-red-700" : ""}`}
                  onClick={handleLocalAgentConnect} disabled={localAgentStatus === "connecting"}>
                  {localAgentStatus === "connecting" ? <Loader2 className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />}
                  {localAgentStatus === "connected" ? t("codeAgent.disconnectLocal") : t("codeAgent.connectLocal")}
                </Button>
              </div>
            )}
          </div>

          {/* Language Switcher */}
          <LanguageSwitcher />

          <div className="w-px h-4 bg-border" />

          {/* Action Buttons */}
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2 text-amber-400 border-amber-400/30 hover:bg-amber-400/10" onClick={handleAiFix} disabled={files.length === 0 || isFixing || isGenerating}>
            {isFixing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Wrench className="w-3 h-3" />} إصلاح الملف
          </Button>
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2 text-primary border-primary/30 hover:bg-primary/10" onClick={handleFixAll} disabled={files.length === 0 || isFixing || isGenerating}>
            {fixAllMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />} إصلاح الكل
          </Button>
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2" onClick={handleCopyAll} disabled={files.length === 0}>
            <Copy className="w-3 h-3" /> {t("common.copy")}
          </Button>
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2" onClick={handleDownloadFile} disabled={files.length === 0}>
            <Download className="w-3 h-3" /> {t("common.download")}
          </Button>
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2 text-emerald-400 border-emerald-400/30 hover:bg-emerald-400/10" onClick={handleDownloadZip} disabled={files.length === 0}>
            <FolderArchive className="w-3 h-3" /> ZIP ↓
          </Button>
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2 text-amber-400 border-amber-400/30 hover:bg-amber-400/10"
            onClick={() => zipInputRef.current?.click()} disabled={isGenerating || uploadingZip}>
            {uploadingZip ? <Loader2 className="w-3 h-3 animate-spin" /> : <FolderArchive className="w-3 h-3" />} ZIP ↑
          </Button>
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2 text-blue-400 border-blue-400/30 hover:bg-blue-400/10" onClick={handleOpenInBYOC} disabled={files.length === 0}>
            <Upload className="w-3 h-3" /> BYOC
          </Button>
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2 text-red-400 border-red-400/30 hover:bg-red-400/10" onClick={handleClear}>
            <Trash2 className="w-3 h-3" /> {t("common.delete")}
          </Button>
        </div>
      </header>

      {/* === MAIN CONTENT === */}
      <div className="flex-1 flex overflow-hidden">
        {/* LEFT: Editor / Preview */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* View Toggle + File Tabs */}
          <div className="h-8 bg-card/50 border-b border-border flex items-center px-1 gap-0.5 overflow-x-auto shrink-0">
            {/* Code View / Live Preview Toggle */}
            <div className="flex items-center bg-secondary/50 rounded-md p-0.5 mr-2 shrink-0">
              <button onClick={() => setEditorView("code")}
                className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold transition-colors ${editorView === "code" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>
                <Code2 className="w-3 h-3" /> {t("codeAgent.codeView")}
              </button>
              <button onClick={() => setEditorView("preview")}
                className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold transition-colors ${editorView === "preview" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>
                <MonitorPlay className="w-3 h-3" /> {t("codeAgent.livePreview")}
              </button>
            </div>

            <div className="w-px h-4 bg-border mr-1" />

            {/* File Tabs */}
            {files.length === 0 ? (
              <span className="text-[10px] text-muted-foreground px-2">{t("codeAgent.taskPlaceholder")}</span>
            ) : files.map((f, i) => (
              <button key={i} onClick={() => { setActiveFileIndex(i); setEditorView("code"); }}
                className={`px-2.5 py-1 text-[11px] rounded-t flex items-center gap-1 transition-colors whitespace-nowrap ${i === activeFileIndex && editorView === "code" ? "bg-background text-foreground border-t-2 border-primary" : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"}`}>
                <FileCode className="w-3 h-3" /> {f.name}
              </button>
            ))}
          </div>

          {/* Editor or Preview Content */}
          <div className={`flex-1 min-h-0 relative ${previewFullscreen ? "fixed inset-0 z-50" : ""}`}>
            {editorView === "preview" ? (
              /* ─── Live Preview ─── */
              <div className="h-full flex flex-col bg-white">
                {/* Preview toolbar */}
                <div className="h-7 bg-card border-b border-border flex items-center justify-between px-3 shrink-0">
                  <div className="flex items-center gap-2">
                    <MonitorPlay className="w-3 h-3 text-emerald-400" />
                    <span className="text-[10px] font-bold text-muted-foreground">{t("codeAgent.livePreview")}</span>
                    {files.some(f => f.name.endsWith(".html")) && (
                      <span className="text-[9px] px-1.5 py-0.5 bg-emerald-500/20 text-emerald-400 rounded">HTML</span>
                    )}
                  </div>
                  <div className="flex items-center gap-1">
                    <Button variant="ghost" size="sm" className="h-5 w-5 p-0" onClick={() => setPreviewFullscreen(!previewFullscreen)}>
                      {previewFullscreen ? <Minimize2 className="w-3 h-3" /> : <Maximize2 className="w-3 h-3" />}
                    </Button>
                    {previewFullscreen && (
                      <Button variant="ghost" size="sm" className="h-5 px-2 text-[10px]" onClick={() => setPreviewFullscreen(false)}>
                        <X className="w-3 h-3" /> ESC
                      </Button>
                    )}
                  </div>
                </div>
                {/* iframe */}
                {files.length > 0 ? (
                  <iframe
                    srcDoc={previewHtml}
                    sandbox="allow-scripts allow-modals allow-forms allow-popups"
                    className="flex-1 w-full border-0"
                    title="Live Preview"
                  />
                ) : (
                  <div className="flex-1 flex flex-col items-center justify-center text-muted-foreground bg-background">
                    <MonitorPlay className="w-16 h-16 mb-4 opacity-20" />
                    <p className="text-lg font-heading">{t("codeAgent.livePreview")}</p>
                    <p className="text-sm mt-1 text-muted-foreground/60">{t("codeAgent.previewEmpty")}</p>
                  </div>
                )}
              </div>
            ) : (
              /* ─── Monaco Editor ─── */
              activeFile ? (
                <Editor height="100%" language={activeFile.language} value={activeFile.content} theme="vs-dark"
                  options={{ readOnly: false, minimap: { enabled: true }, fontSize: 13, fontFamily: "'JetBrains Mono', monospace", lineNumbers: "on", scrollBeyondLastLine: false, wordWrap: "on", padding: { top: 8 }, renderLineHighlight: "gutter", automaticLayout: true, tabSize: 2, bracketPairColorization: { enabled: true }, guides: { bracketPairs: true } }}
                  onChange={(value) => { if (value !== undefined) setFiles((prev) => { const u = [...prev]; u[activeFileIndex] = { ...u[activeFileIndex], content: value }; return u; }); }} />
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                  <Code2 className="w-16 h-16 mb-4 opacity-20" />
                  <p className="text-lg font-heading">{t("codeAgent.codeEditor")}</p>
                  <p className="text-sm mt-1 text-muted-foreground/60">{t("codeAgent.previewEmpty")}</p>
                </div>
              )
            )}
          </div>

          {/* Status Bar */}
          <div className="h-6 bg-card/50 border-t border-border flex items-center justify-between px-3 text-[10px] text-muted-foreground shrink-0">
            <div className="flex items-center gap-3">
              {isGenerating ? <span className="flex items-center gap-1 text-amber-400"><Loader2 className="w-3 h-3 animate-spin" /> {t("codeAgent.generating")}</span>
                : isFixing ? <span className="flex items-center gap-1 text-amber-400"><Loader2 className="w-3 h-3 animate-spin" /> {t("codeAgent.fixing")}</span>
                : files.length > 0 ? <span className="text-emerald-400">{t("common.success")}</span>
                : <span className="text-muted-foreground">Ready</span>}
            </div>
            <div className="flex items-center gap-3">
              <span>{t("common.files")}: {fileCount}</span>
              {activeFile && <span>{activeFile.language}</span>}
              <span className="text-violet-400">{AI_MODELS.find((m) => m.id === selectedModel)?.icon} {AI_MODELS.find((m) => m.id === selectedModel)?.name.split(" ")[0]}</span>
              {editorView === "preview" && <span className="text-emerald-400 flex items-center gap-1"><MonitorPlay className="w-3 h-3" /> LIVE</span>}
            </div>
          </div>
        </div>

        {/* RIGHT: Mission + Categories + Workflow + Console */}
        <div className="w-[360px] border-l border-border flex flex-col bg-card/30 shrink-0">
          {/* Mission Briefing */}
          <div className="p-3 border-b border-border">
            <h3 className="font-heading font-bold text-sm mb-2 flex items-center gap-2">
              <Bot className="w-4 h-4 text-primary" /> {t("codeAgent.missionBriefing")}
            </h3>
            <textarea ref={textareaRef} value={prompt} onChange={(e) => setPrompt(e.target.value)}
              placeholder={t("codeAgent.taskPlaceholder")}
              className="w-full h-20 bg-background border border-border rounded-lg p-3 text-sm resize-none focus:outline-none focus:ring-1 focus:ring-primary placeholder:text-muted-foreground/50"
              disabled={isGenerating}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleExecute(); } }} />

            {/* Action row: Paste + Upload Design */}
            <div className="flex gap-2 mt-2">
              <Button variant="outline" size="sm" className="text-xs gap-1 flex-1"
                onClick={() => navigator.clipboard.readText().then((text) => { setPrompt((prev) => prev + (prev ? "\n" : "") + text); toast.success(t("common.success")); }).catch(() => toast.error(t("common.error")))}
                disabled={isGenerating}>
                <FileText className="w-3 h-3" /> {t("codeAgent.pasteCode")}
              </Button>
              <Button variant="outline" size="sm" className="text-xs gap-1 flex-1 text-violet-400 border-violet-400/30 hover:bg-violet-400/10"
                onClick={() => imageInputRef.current?.click()}
                disabled={isGenerating || uploadingImage}>
                {uploadingImage ? <Loader2 className="w-3 h-3 animate-spin" /> : <Image className="w-3 h-3" />}
                {t("codeAgent.uploadDesign")}
              </Button>
              <Button variant="outline" size="sm" className="text-xs gap-1 flex-1 text-emerald-400 border-emerald-400/30 hover:bg-emerald-400/10"
                onClick={() => zipInputRef.current?.click()}
                disabled={isGenerating || uploadingZip}>
                {uploadingZip ? <Loader2 className="w-3 h-3 animate-spin" /> : <FolderArchive className="w-3 h-3" />}
                {uploadingZip ? "جاري الاستخراج..." : "رفع ZIP/RAR"}
              </Button>
              <input ref={imageInputRef} type="file" accept="image/*" className="hidden" onChange={handleUploadDesign} />
              <input ref={zipInputRef} type="file" accept=".zip,.rar,application/zip,application/x-zip-compressed,application/x-rar-compressed,application/vnd.rar" className="hidden" onChange={handleUploadZip} />
            </div>

            {/* Pipeline Mode toggle */}
            <button
              onClick={() => setPipelineMode((v) => !v)}
              disabled={isGenerating}
              className={`w-full mt-2 flex items-center justify-between px-3 py-1.5 rounded-lg border text-xs transition-all ${
                pipelineMode
                  ? "border-violet-500/60 bg-violet-500/10 text-violet-300"
                  : "border-border text-muted-foreground hover:text-foreground hover:border-border/80"
              }`}
            >
              <span className="flex items-center gap-1.5">
                <Sparkles className="w-3 h-3" />
                Pipeline Mode (4 نماذج)
              </span>
              {pipelineMode && (
                <span className="text-[9px] bg-violet-500/20 text-violet-300 px-1.5 py-0.5 rounded-full flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse inline-block" />
                  Claude Sonnet → Opus → DeepSeek → Gemini
                </span>
              )}
            </button>

            <Button onClick={handleExecute} disabled={!prompt.trim() || isGenerating}
              className={`w-full mt-2 gap-2 font-bold text-base h-10 text-white ${pipelineMode ? "bg-violet-700 hover:bg-violet-800" : "bg-emerald-600 hover:bg-emerald-700"}`} size="lg">
              {isGenerating ? <Loader2 className="w-5 h-5 animate-spin" /> : <Play className="w-5 h-5" />}
              {isGenerating
                ? (pipelineMode ? "جارٍ تشغيل الـ Pipeline..." : t("codeAgent.generating"))
                : (pipelineMode ? "تشغيل Pipeline" : t("codeAgent.execute"))}
            </Button>
          </div>

          {/* Categories */}
          <div className="border-b border-border">
            <button onClick={() => setShowCategories(!showCategories)}
              className="w-full px-3 py-2 flex items-center justify-between text-[10px] font-bold text-muted-foreground hover:text-foreground transition-colors">
              <span>{t("codeAgent.category")} ({CATEGORIES.length})</span>
              {showCategories ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            </button>
            {showCategories && (
              <div className="px-3 pb-2 space-y-0.5 max-h-[250px] overflow-y-auto">
                {CATEGORIES.map((cat) => {
                  const Icon = cat.icon;
                  const isCyber = ["pentest", "network", "defense", "forensics"].includes(cat.id);
                  return (
                    <button key={cat.id} onClick={() => setSelectedCategory(selectedCategory === cat.id ? null : cat.id)}
                      className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded text-[10px] transition-colors ${selectedCategory === cat.id ? "bg-primary/20 text-primary ring-1 ring-primary/30" : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"}`}>
                      <Icon className="w-3 h-3 shrink-0" style={{ color: cat.color }} />
                      <span className="font-bold">{cat.nameEn}</span>
                      <span className="text-muted-foreground/60 text-[9px]">{cat.name}</span>
                      {isCyber && <span className="ml-auto text-[8px] px-1 py-0.5 bg-red-500/20 text-red-400 rounded">CYBER</span>}
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Workflow Status */}
          <div className="px-3 py-2 border-b border-border">
            <h4 className="text-[10px] font-bold text-muted-foreground mb-1.5">{t("codeAgent.workflow")}</h4>
            <div className="flex gap-1 flex-wrap">
              {WORKFLOW_STEPS.map((step) => {
                const stepIndex = WORKFLOW_STEPS.findIndex((s) => s.id === step.id);
                const currentIndex = WORKFLOW_STEPS.findIndex((s) => s.id === workflowStep);
                const isActive = step.id === workflowStep;
                const isCompleted = currentIndex > stepIndex;
                const isIdle = workflowStep === "idle";
                return (
                  <div key={step.id}
                    className={`flex items-center gap-1 px-2 py-1 rounded text-[9px] font-mono font-bold transition-all ${isActive ? "bg-primary/20 text-primary ring-1 ring-primary/50 animate-pulse" : isCompleted ? "bg-emerald-500/20 text-emerald-400" : isIdle ? "bg-secondary/50 text-muted-foreground" : "bg-secondary/30 text-muted-foreground/50"}`}>
                    {isCompleted ? <CheckCircle2 className="w-2.5 h-2.5" /> : isActive ? <Loader2 className="w-2.5 h-2.5 animate-spin" /> : <Circle className="w-2.5 h-2.5" />}
                    {step.label}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Console */}
          <div className="flex-1 flex flex-col min-h-0">
            <div className="px-3 py-1.5 flex items-center gap-2 shrink-0 border-b border-border/50">
              <div className="flex gap-1"><div className="w-2.5 h-2.5 rounded-full bg-red-500" /><div className="w-2.5 h-2.5 rounded-full bg-amber-500" /><div className="w-2.5 h-2.5 rounded-full bg-emerald-500" /></div>
              <span className="text-[10px] font-mono text-muted-foreground">hayo@agent:~$</span>
            </div>
            <div ref={consoleRef} className="flex-1 overflow-y-auto px-3 py-2 font-mono text-[10px] space-y-0.5 bg-black/20">
              {consoleLogs.map((log, i) => (
                <div key={i} className={`${logColor(log.type)} leading-relaxed`}>
                  <span className="text-muted-foreground/50">[{log.time}]</span> {log.message}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
