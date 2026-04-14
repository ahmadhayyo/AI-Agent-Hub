import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { trpc } from "@/lib/trpc";
import CreditsBar from "@/components/CreditsBar";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { Streamdown } from "streamdown";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import { useTranslation } from "react-i18next";
import {
  Send, Loader2, Plus, Paperclip, Trash2, MessageSquare,
  User, FileText, Image as ImageIcon, FileCode,
  FileSpreadsheet, X, ChevronLeft, Zap, Bot,
  Copy, Check, ArrowRight, Globe,
  Download, ChevronDown, ChevronUp, Terminal,
  Wrench, Brain, Eye, CheckCircle2, Crown, AlertTriangle, FolderArchive,
  Mic, MicOff, Volume2, VolumeX, ImagePlus, Video,
} from "lucide-react";
import { useState, useEffect, useRef, useCallback } from "react";
import { Link } from "wouter";
import { toast } from "sonner";

const HAYO_LOGO = `${import.meta.env.BASE_URL ?? "/"}logo.png`;
const API_BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

// ============================================================
// AI Models (same as CodeAgent)
// ============================================================
const AI_MODELS = [
  { id: "default", name: "HAYO Default", icon: "🤖", color: "text-primary", desc: "Claude Sonnet 4.5" },
  { id: "claude-sonnet", name: "Claude Sonnet", icon: "🟣", color: "text-violet-400", desc: "Anthropic claude-sonnet-4-5" },
  { id: "gpt-4o", name: "GPT-4o Mini", icon: "🟢", color: "text-emerald-400", desc: "OpenAI gpt-4o-mini" },
  { id: "deepseek-coder", name: "DeepSeek R1", icon: "🔵", color: "text-blue-400", desc: "DeepSeek Reasoner" },
  { id: "gemini-pro", name: "Gemini Flash", icon: "🔴", color: "text-red-400", desc: "Google gemini-2.0-flash" },
  { id: "groq-llama", name: "Groq LLaMA", icon: "⚡", color: "text-amber-400", desc: "llama-3.3-70b-versatile" },
  { id: "mistral-large", name: "Mistral Large", icon: "🟠", color: "text-orange-400", desc: "mistral-large-latest" },
];

// ============================================================
// Types
// ============================================================
type Attachment = {
  name: string;
  url: string;
  type: string;
  size: number;
  extractedText?: string;
  preview?: string;
};

type AgentStep = {
  type: "thinking" | "tool_call" | "tool_result" | "response";
  content: string;
  toolName?: string;
  toolArgs?: Record<string, any>;
  success?: boolean;
  imageUrl?: string;
  fileUrl?: string;
  timestamp: number;
};

type ChatMessage = {
  id?: number;
  role: "user" | "assistant" | "system";
  content: string;
  attachments?: Attachment[];
  steps?: AgentStep[];
  createdAt?: Date;
};

// ============================================================
// Helper Components
// ============================================================
function getFileIcon(mimeType: string) {
  if (mimeType.startsWith("image/")) return <ImageIcon className="size-4" />;
  if (mimeType.includes("pdf")) return <FileText className="size-4" />;
  if (mimeType.includes("spreadsheet") || mimeType.includes("csv") || mimeType.includes("excel"))
    return <FileSpreadsheet className="size-4" />;
  if (mimeType.includes("zip") || mimeType.includes("x-zip") || mimeType.includes("rar") || mimeType.includes("vnd.rar"))
    return <FolderArchive className="size-4 text-emerald-400" />;
  if (mimeType.includes("javascript") || mimeType.includes("python") || mimeType.includes("json") || mimeType.includes("text/"))
    return <FileCode className="size-4" />;
  return <FileText className="size-4" />;
}

function detectLangForMarkdown(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  const map: Record<string, string> = {
    js: "javascript", jsx: "javascript", ts: "typescript", tsx: "typescript",
    py: "python", html: "html", css: "css", json: "json", md: "markdown",
    sql: "sql", sh: "shell", yml: "yaml", yaml: "yaml", xml: "xml",
    java: "java", cpp: "cpp", c: "c", rb: "ruby", php: "php",
    go: "go", rs: "rust", swift: "swift", kt: "kotlin", dart: "dart",
  };
  return map[ext] || "";
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function getToolIcon(toolName?: string) {
  switch (toolName) {
    case "execute_python": case "execute_javascript": return <Terminal className="size-3.5" />;
    case "analyze_file": return <Eye className="size-3.5" />;
    case "web_search": return <Globe className="size-3.5" />;
    case "generate_image": return <ImageIcon className="size-3.5" />;
    case "create_file": return <Download className="size-3.5" />;
    default: return <Wrench className="size-3.5" />;
  }
}

function getToolColor(toolName?: string) {
  switch (toolName) {
    case "execute_python": case "execute_javascript": return "from-emerald-500 to-green-600";
    case "analyze_file": return "from-blue-500 to-cyan-600";
    case "web_search": return "from-amber-500 to-orange-600";
    case "generate_image": return "from-purple-500 to-pink-600";
    case "create_file": return "from-indigo-500 to-violet-600";
    default: return "from-gray-500 to-gray-600";
  }
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={handleCopy} className="p-1 rounded hover:bg-accent/50 text-muted-foreground hover:text-foreground transition-colors">
      {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
    </button>
  );
}

// ============================================================
// Agent Steps Display Component
// ============================================================
function AgentStepsDisplay({ steps }: { steps: AgentStep[] }) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(true);
  const toolSteps = steps.filter(s => s.type === "tool_call" || s.type === "tool_result" || s.type === "thinking");

  if (toolSteps.length === 0) return null;

  return (
    <div className="mb-3">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors mb-2"
      >
        <Brain className="size-3.5" />
        <span className="font-medium">{t("chat.executionSteps")} ({toolSteps.filter(s => s.type === "tool_call").length} {t("chat.tools")})</span>
        {expanded ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />}
      </button>

      {expanded && (
        <div className="space-y-1.5 mr-1 border-r-2 border-primary/20 pr-3">
          {toolSteps.map((step, i) => (
            <div key={i} className="flex items-start gap-2">
              {step.type === "thinking" && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground py-1">
                  <div className="w-5 h-5 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                    <Brain className="size-3 text-primary" />
                  </div>
                  <span>{step.content}</span>
                </div>
              )}

              {step.type === "tool_call" && (
                <div className="flex items-center gap-2 text-xs py-1">
                  <div className={cn(
                    "w-5 h-5 rounded-full bg-gradient-to-br flex items-center justify-center shrink-0 text-white",
                    getToolColor(step.toolName)
                  )}>
                    {getToolIcon(step.toolName)}
                  </div>
                  <span className="font-medium text-foreground">{step.content}</span>
                </div>
              )}

              {step.type === "tool_result" && (
                <div className="flex items-start gap-2 text-xs py-1 w-full">
                  <div className={cn(
                    "w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5",
                    step.success !== false ? "bg-emerald-500/10 text-emerald-500" : "bg-red-500/10 text-red-500"
                  )}>
                    {step.success !== false ? <Check className="size-3" /> : <X className="size-3" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    {step.imageUrl && (
                      <img src={step.imageUrl} alt="Generated" className="max-w-xs rounded-lg border border-border mt-1 mb-1" />
                    )}
                    {step.fileUrl && (
                      <a href={step.fileUrl} target="_blank" rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition-colors mt-1">
                        <Download className="size-3" />
                        <span>{t("chat.downloadFile")}</span>
                      </a>
                    )}
                    {!step.imageUrl && !step.fileUrl && step.content && (
                      <div className="bg-accent/30 rounded-lg p-2 mt-1 border border-border">
                        <pre className="text-[11px] text-foreground/80 whitespace-pre-wrap break-all max-h-40 overflow-auto">
                          {step.content.substring(0, 500)}{step.content.length > 500 ? "\n..." : ""}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ============================================================
// Loading Progress Component
// ============================================================
function LoadingProgress() {
  const { t } = useTranslation();
  const [elapsed, setElapsed] = useState(0);
  const [phase, setPhase] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => setElapsed(prev => prev + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (elapsed < 3) setPhase(0);
    else if (elapsed < 8) setPhase(1);
    else if (elapsed < 15) setPhase(2);
    else if (elapsed < 25) setPhase(3);
    else setPhase(4);
  }, [elapsed]);

  const phases = [
    { text: t("chat.analyzing"), icon: Brain },
    { text: t("chat.choosingTools"), icon: Wrench },
    { text: t("chat.executingTasks"), icon: Terminal },
    { text: t("chat.collectingResults"), icon: Download },
    { text: t("chat.processing"), icon: Loader2 },
  ];

  const CurrentIcon = phases[phase].icon;

  return (
    <div className="mb-6">
      <div className="flex items-start gap-3">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center shrink-0">
          <Bot className="size-4 text-white" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-3 py-2">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-primary/5 border border-primary/10">
              <CurrentIcon className="size-4 text-primary animate-pulse" />
              <span className="text-sm text-foreground/80">{phases[phase].text}</span>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-1">
            <div className="flex gap-1">
              <div className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: "0ms" }} />
              <div className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: "150ms" }} />
              <div className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: "300ms" }} />
            </div>
            <span className="text-[11px] text-muted-foreground">{elapsed} {t("chat.seconds")}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// Main Chat Component
// ============================================================
export default function Chat() {
  const { t } = useTranslation();
  const { user, loading: authLoading, isAuthenticated } = useAuth();
  const [activeConvId, setActiveConvId] = useState<number | null>(null);
  const [localMessages, setLocalMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [pendingFiles, setPendingFiles] = useState<Attachment[]>([]);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [selectedModel, setSelectedModel] = useState("default");
  const [showModelSelector, setShowModelSelector] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Voice input/output
  const [isRecording, setIsRecording] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);

  // Image generation
  const [showImageGen, setShowImageGen] = useState(false);
  const [imagePrompt, setImagePrompt] = useState("");
  const [generatingImage, setGeneratingImage] = useState(false);

  // Video generation (Owner only)
  const [showVideoGen, setShowVideoGen] = useState(false);
  const [videoPrompt, setVideoPrompt] = useState("");
  const [videoModel, setVideoModel] = useState("minimax");
  const [videoAspect, setVideoAspect] = useState("16:9");
  const [generatingVideo, setGeneratingVideo] = useState(false);
  const isOwnerUser = user?.role === "admin";

  // Voice Input: Start/Stop recording
  const toggleRecording = useCallback(async () => {
    if (isRecording) {
      mediaRecorderRef.current?.stop();
      setIsRecording(false);
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream);
      audioChunksRef.current = [];
      recorder.ondataavailable = (e) => audioChunksRef.current.push(e.data);
      recorder.onstop = async () => {
        stream.getTracks().forEach(t => t.stop());
        const blob = new Blob(audioChunksRef.current, { type: "audio/webm" });
        // Convert to text using Web Speech API
        try {
          const recognition = new (window as any).webkitSpeechRecognition || new (window as any).SpeechRecognition();
          recognition.lang = "ar-SA";
          recognition.continuous = false;
          recognition.interimResults = false;
          recognition.onresult = (event: any) => {
            const text = event.results[0][0].transcript;
            setInput(prev => prev + (prev ? " " : "") + text);
          };
          recognition.start();
          // Timeout after 10s
          setTimeout(() => { try { recognition.stop(); } catch {} }, 10000);
        } catch {
          toast.error("المتصفح لا يدعم تحويل الصوت للنص");
        }
      };
      recorder.start();
      mediaRecorderRef.current = recorder;
      setIsRecording(true);
      toast.info("🎤 جاري التسجيل... اضغط مرة أخرى للإيقاف");
      // Auto stop after 60s
      setTimeout(() => { if (mediaRecorderRef.current?.state === "recording") { mediaRecorderRef.current.stop(); setIsRecording(false); } }, 60000);
    } catch {
      toast.error("لم يتم السماح بالوصول للميكروفون");
    }
  }, [isRecording]);

  // Voice Output: Read message aloud
  const speakText = useCallback((text: string) => {
    if (isSpeaking) { window.speechSynthesis.cancel(); setIsSpeaking(false); return; }
    const clean = text.replace(/[#*`_~\[\]()>|]/g, "").replace(/\n+/g, ". ");
    const utterance = new SpeechSynthesisUtterance(clean);
    utterance.lang = "ar-SA";
    utterance.rate = 0.9;
    utterance.onend = () => setIsSpeaking(false);
    utterance.onerror = () => setIsSpeaking(false);
    window.speechSynthesis.speak(utterance);
    setIsSpeaking(true);
  }, [isSpeaking]);

  // Image Generation
  const handleGenerateImage = useCallback(async () => {
    if (!imagePrompt.trim()) return;
    setGeneratingImage(true);
    try {
      const res = await fetch(`${API_BASE}/api/chat/generate-image`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: imagePrompt }),
      });
      const data = await res.json();
      if (data.error) { toast.error(data.error); return; }
      // Add image as assistant message
      const imgMsg: ChatMessage = {
        role: "assistant",
        content: `![${imagePrompt}](${data.imageUrl})\n\n🎨 **صورة مُولّدة:** ${imagePrompt}`,
        createdAt: new Date(),
      };
      setLocalMessages(prev => [...prev, imgMsg]);
      setShowImageGen(false);
      setImagePrompt("");
      toast.success("تم توليد الصورة! 🎨");
    } catch (e: any) { toast.error(e.message); }
    finally { setGeneratingImage(false); }
  }, [imagePrompt]);

  // Video Generation (Owner only)
  const handleGenerateVideo = useCallback(async () => {
    if (!videoPrompt.trim()) return;
    setGeneratingVideo(true);
    toast.info("🎬 جاري توليد الفيديو... قد يستغرق 2-5 دقائق");
    try {
      const res = await fetch(`${API_BASE}/api/chat/generate-video`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: videoPrompt, model: videoModel, aspectRatio: videoAspect }),
      });
      const data = await res.json();
      if (data.error) { toast.error(data.error); return; }
      const vidMsg: ChatMessage = {
        role: "assistant",
        content: `🎬 **فيديو AI — ${videoModel}**\n\n${videoPrompt}\n\n<video controls style="max-width:100%;border-radius:12px;" src="${data.videoUrl}"></video>\n\n⏱️ وقت التوليد: ${data.duration || "غير محدد"}`,
        createdAt: new Date(),
      };
      setLocalMessages(prev => [...prev, vidMsg]);
      setShowVideoGen(false);
      setVideoPrompt("");
      toast.success("🎬 تم توليد الفيديو بنجاح!");
    } catch (e: any) { toast.error(e.message); }
    finally { setGeneratingVideo(false); }
  }, [videoPrompt, videoModel, videoAspect]);
  const modelSelectorRef = useRef<HTMLDivElement>(null);

  const convListQuery = trpc.conversations.list.useQuery(undefined, {
    enabled: isAuthenticated,
    staleTime: 30000,
  });
  const convDetailQuery = trpc.conversations.get.useQuery(
    { id: activeConvId! },
    { enabled: !!activeConvId, staleTime: 10000 }
  );
  const limitQuery = trpc.subscriptions.checkLimit.useQuery(undefined, {
    enabled: isAuthenticated,
    staleTime: 60000,
    refetchInterval: 60000,
  });

  const createConvMutation = trpc.conversations.create.useMutation({
    onSuccess: (data: any) => {
      setActiveConvId(data.id);
      setLocalMessages([]);
      convListQuery.refetch();
    },
  });

  const deleteConvMutation = trpc.conversations.delete.useMutation({
    onSuccess: () => {
      if (activeConvId) {
        setActiveConvId(null);
        setLocalMessages([]);
      }
      convListQuery.refetch();
    },
  });

  const uploadMutation = trpc.files.upload.useMutation();

  // SSE streaming chat
  const sendStreamingMessage = useCallback(async (
    convId: number,
    message: string,
    model: string,
    attachments?: Attachment[]
  ) => {
    // Add a streaming placeholder message
    const streamingId = Date.now();
    setLocalMessages(prev => [...prev, {
      id: streamingId as any,
      role: "assistant" as const,
      content: "",
      createdAt: new Date(),
      _streaming: true,
    } as any]);

    try {
      const res = await fetch(`${API_BASE}/api/chat/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          conversationId: convId,
          message,
          model,
          messages: [{ role: "user", content: message }],
          attachments: attachments?.map(a => ({
            name: a.name, url: a.url, type: a.type, size: a.size, extractedText: a.extractedText,
          })),
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as any).error || `HTTP ${res.status}`);
      }

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const event = JSON.parse(line.slice(6));
            if (event.type === "chunk") {
              setLocalMessages(prev => prev.map(m =>
                (m as any)._streaming && m.role === "assistant"
                  ? { ...m, content: m.content + event.text }
                  : m
              ));
            } else if (event.type === "step") {
              setLocalMessages(prev => prev.map(m =>
                (m as any)._streaming && m.role === "assistant"
                  ? { ...m, steps: [...(m.steps || []), event.step] }
                  : m
              ));
            } else if (event.type === "done") {
              setLocalMessages(prev => prev.map(m =>
                (m as any)._streaming && m.role === "assistant"
                  ? {
                      ...m,
                      id: event.messageId,
                      content: event.fullText,
                      steps: event.steps?.length ? event.steps : m.steps,
                      _streaming: false,
                    }
                  : m
              ));
              convListQuery.refetch();
            } else if (event.type === "error") {
              throw new Error(event.error);
            }
          } catch (_) {}
        }
      }
    } catch (err: any) {
      setLocalMessages(prev => prev.map(m =>
        (m as any)._streaming && m.role === "assistant"
          ? { ...m, content: `${t("common.error")}: ${err.message}`, _streaming: false }
          : m
      ));
    } finally {
      setIsAiLoading(false);
    }
  }, [convListQuery, t]);

  useEffect(() => {
    if (convDetailQuery.data) {
      setLocalMessages(convDetailQuery.data.messages.map((m: any) => ({
        id: m.id,
        role: m.role as "user" | "assistant",
        content: m.content,
        attachments: m.attachments as Attachment[] | undefined,
        createdAt: m.createdAt,
      })));
    }
  }, [convDetailQuery.data]);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const scrollToBottom = useCallback(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(scrollToBottom, 100);
    return () => clearTimeout(timer);
  }, [localMessages, isAiLoading, scrollToBottom]);

  // Close model selector when clicking outside
  useEffect(() => {
    if (!showModelSelector) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (modelSelectorRef.current && !modelSelectorRef.current.contains(e.target as Node)) {
        setShowModelSelector(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [showModelSelector]);

  const handleFileSelect = useCallback(async (files: FileList) => {
    const maxSize = 10 * 1024 * 1024;
    const zipMaxSize = 50 * 1024 * 1024;

    // Owner/admin: unlimited file size
    const isOwner = user?.role === "admin";
    const effectiveMaxSize = isOwner ? 500 * 1024 * 1024 : maxSize; // 500MB for owner
    const effectiveZipMax = isOwner ? 500 * 1024 * 1024 : zipMaxSize;
    const newFiles: Attachment[] = [];

    for (const file of Array.from(files)) {
      const isZip = file.name.toLowerCase().endsWith(".zip") ||
        file.type === "application/zip" ||
        file.type === "application/x-zip-compressed";

      const isRar = file.name.toLowerCase().endsWith(".rar") ||
        file.type === "application/x-rar-compressed" || file.type === "application/vnd.rar";

      if (isZip || isRar) {
        if (file.size > effectiveZipMax) {
          alert(`${file.name}: الحجم يتجاوز 50MB`);
          continue;
        }
        try {
          let fileEntries: { name: string; content: string }[] = [];

          if (isZip) {
            // Client-side ZIP extraction
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
                if (content.length < 500_000) fileEntries.push({ name: filename, content });
              } catch {}
            }
          } else {
            // RAR: backend extraction
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
            fileEntries = data.files as { name: string; content: string }[];
          }

          fileEntries.sort((a, b) => a.name.localeCompare(b.name));

          let extractedText = `📦 **${file.name}** — ${fileEntries.length} ملف مستخرج\n\n`;
          extractedText += `**هيكل المشروع:**\n${fileEntries.map(f => `- \`${f.name}\``).join("\n")}\n\n---\n\n`;
          fileEntries.forEach(f => {
            const lang = detectLangForMarkdown(f.name);
            extractedText += `### ${f.name}\n\`\`\`${lang}\n${f.content.slice(0, 15000)}\n\`\`\`\n\n`;
          });

          newFiles.push({
            name: file.name,
            url: "",
            type: isRar ? "application/x-rar-compressed" : "application/zip",
            size: file.size,
            extractedText,
          });
        } catch (err) {
          alert(`فشل استخراج ${file.name}: ${(err as any).message}`);
        }
        continue;
      }

      if (file.size > effectiveMaxSize) {
        alert(`${file.name} ${t("chat.fileTooLarge")}`);
        continue;
      }

      const reader = new FileReader();
      const base64 = await new Promise<string>((resolve) => {
        reader.onload = () => resolve((reader.result as string).split(",")[1]);
        reader.readAsDataURL(file);
      });

      let preview: string | undefined;
      if (file.type.startsWith("image/")) {
        preview = `data:${file.type};base64,${base64}`;
      }

      let extractedText: string | undefined;
      if (file.type.startsWith("text/") || file.type.includes("json") || file.type.includes("csv") ||
          file.type.includes("javascript") || file.type.includes("python") || file.type.includes("xml")) {
        extractedText = await file.text();
      }

      newFiles.push({
        name: file.name,
        url: "",
        type: file.type,
        size: file.size,
        preview,
        extractedText,
      });

      try {
        const result = await uploadMutation.mutateAsync({
          fileName: file.name,
          fileData: base64,
          mimeType: file.type,
          fileSize: file.size,
        });
        newFiles[newFiles.length - 1].url = result.url;
      } catch (err) {
        console.error("Upload failed:", err);
      }
    }

    setPendingFiles(prev => [...prev, ...newFiles]);
  }, [uploadMutation, t]);

  const removePendingFile = useCallback((index: number) => {
    setPendingFiles(prev => prev.filter((_, i) => i !== index));
  }, []);

  const handleSend = useCallback(async () => {
    const trimmed = input.trim();
    if (!trimmed && pendingFiles.length === 0) return;
    if (isAiLoading) return;

    let convId = activeConvId;
    if (!convId) {
      const conv = await createConvMutation.mutateAsync({});
      convId = conv.id;
    }

    const attachments = pendingFiles.length > 0 ? [...pendingFiles] : undefined;
    const userMessage: ChatMessage = {
      role: "user",
      content: trimmed || t("chat.analyzeAttached"),
      attachments,
      createdAt: new Date(),
    };

    setLocalMessages(prev => [...prev, userMessage]);
    setInput("");
    setPendingFiles([]);
    setIsAiLoading(true);

    sendStreamingMessage(convId!, userMessage.content, selectedModel, attachments);
  }, [input, pendingFiles, isAiLoading, activeConvId, createConvMutation, sendStreamingMessage, selectedModel, t]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }, [handleSend]);

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
  }, []);

  const [isDragging, setIsDragging] = useState(false);
  const handleDragOver = useCallback((e: React.DragEvent) => { e.preventDefault(); setIsDragging(true); }, []);
  const handleDragLeave = useCallback(() => setIsDragging(false), []);
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files.length > 0) handleFileSelect(e.dataTransfer.files);
  }, [handleFileSelect]);

  // ============================================================
  // Auth Loading / Not Authenticated
  // ============================================================
  if (authLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="size-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center space-y-6 max-w-md px-4">
          <img src={HAYO_LOGO} alt="HAYO AI" className="w-16 h-16 rounded-2xl mx-auto shadow-lg shadow-indigo-500/25" />
          <h1 className="text-2xl font-heading font-bold">HAYO AI AGENT</h1>
          <p className="text-muted-foreground">{t("chat.loginPrompt")}</p>
          <a href={getLoginUrl()}>
            <Button size="lg" className="bg-gradient-to-r from-indigo-500 to-violet-600 text-white">
              {t("common.login")}
              <ArrowRight className="size-4 mr-2 rtl:rotate-180" />
            </Button>
          </a>
        </div>
      </div>
    );
  }

  const conversations = convListQuery.data || [];
  const displayMessages = localMessages.filter(m => m.role !== "system");
  const currentModel = AI_MODELS.find(m => m.id === selectedModel) || AI_MODELS[0];

  // ============================================================
  // Main Chat UI
  // ============================================================
  return (
    <div className="h-screen bg-background flex overflow-hidden"
         onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}>

      {/* Sidebar */}
      <div className={cn(
        "border-r border-border bg-card flex flex-col transition-all duration-300",
        sidebarOpen ? "w-72" : "w-0 overflow-hidden"
      )}>
        <div className="p-3 border-b border-border">
          <Link href="/" className="flex items-center gap-2 mb-3 px-1">
            <img src={HAYO_LOGO} alt="HAYO AI" className="w-7 h-7 rounded-lg" />
            <span className="font-heading font-bold text-sm">HAYO AI</span>
            {user?.role === "admin" && (
              <span className="text-[9px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 font-bold">{t("common.owner") || "مالك"}</span>
            )}
          </Link>
          {user?.role === "admin" && (
            <div className="flex items-center gap-2 text-[10px] text-emerald-400 bg-emerald-500/10 rounded-lg px-2 py-1 mb-2">
              <Crown className="size-3" />
              <span>{t("common.unlimitedAccess") || "وصول غير محدود — بلا حدود رفع أو نقاط"}</span>
            </div>
          )}
          <Button
            onClick={() => { setActiveConvId(null); setLocalMessages([]); setPendingFiles([]); }}
            className="w-full bg-gradient-to-r from-indigo-500 to-violet-600 text-white hover:from-indigo-600 hover:to-violet-700"
            size="sm"
          >
            <Plus className="size-4 ml-1" />
            {t("chat.newConversation")}
          </Button>
        </div>

        <ScrollArea className="flex-1">
          <div className="p-2 space-y-0.5">
            {conversations.map((conv: any) => (
              <div
                key={conv.id}
                className={cn(
                  "group flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer text-sm transition-colors",
                  activeConvId === conv.id
                    ? "bg-primary/10 text-primary"
                    : "hover:bg-accent/50 text-muted-foreground hover:text-foreground"
                )}
                onClick={() => setActiveConvId(conv.id)}
              >
                <MessageSquare className="size-4 shrink-0" />
                <span className="truncate flex-1">{conv.title}</span>
                <button
                  onClick={(e) => { e.stopPropagation(); deleteConvMutation.mutate({ id: conv.id }); }}
                  className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive transition-all"
                >
                  <Trash2 className="size-3.5" />
                </button>
              </div>
            ))}
          </div>
        </ScrollArea>

        {/* Credits Bar */}
        <div className="px-3 pb-1 border-t border-border pt-3">
          <CreditsBar operationCost={2} />
        </div>

        {/* Capabilities Badge */}
        <div className="p-3">
          <div className="text-[10px] text-muted-foreground space-y-1">
            <div className="font-medium text-foreground/70 mb-1.5">{t("chat.capabilities")}:</div>
            <div className="flex flex-wrap gap-1">
              {[
                { icon: Terminal, label: t("chat.executeCode"), color: "text-emerald-500" },
                { icon: Eye, label: t("chat.analyzeFiles"), color: "text-blue-500" },
                { icon: Globe, label: t("chat.webSearch"), color: "text-amber-500" },
                { icon: ImageIcon, label: t("chat.generateImages"), color: "text-purple-500" },
                { icon: Download, label: t("chat.createFiles"), color: "text-indigo-500" },
              ].map(({ icon: Icon, label, color }) => (
                <span key={label} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-accent/50">
                  <Icon className={cn("size-2.5", color)} />
                  {label}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <div className="h-12 border-b border-border bg-card/50 flex items-center px-4 shrink-0">
          <Button
            variant="ghost"
            size="icon"
            className="size-8 ml-2"
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            <ChevronLeft className={cn("size-4 transition-transform", !sidebarOpen && "rotate-180")} />
          </Button>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center">
              <Bot className="size-3.5 text-white" />
            </div>
            <span className="font-heading font-semibold text-sm">HAYO AI AGENT</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 font-medium">
              {t("chat.executiveAgent")}
            </span>
          </div>
          <div className="mr-auto" />

          {/* Model Switcher */}
          <div className="relative" ref={modelSelectorRef}>
            <Button variant="ghost" size="sm" className="text-[10px] gap-1.5 h-8 px-2.5"
              onClick={() => setShowModelSelector(!showModelSelector)}>
              <span className="text-base leading-none">{currentModel.icon}</span>
              <span className="hidden sm:inline font-bold">{currentModel.name}</span>
              <ChevronDown className="size-3 text-muted-foreground" />
            </Button>
            {showModelSelector && (
              <div className="absolute top-full right-0 mt-1 w-64 bg-card border border-border rounded-xl shadow-xl z-50 p-2 space-y-0.5">
                <div className="px-2 py-1 text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
                  {t("chat.modelSwitcher")}
                </div>
                {AI_MODELS.map((model) => (
                  <button key={model.id}
                    onClick={() => { setSelectedModel(model.id); setShowModelSelector(false); }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition-colors ${
                      selectedModel === model.id
                        ? "bg-primary/15 text-primary ring-1 ring-primary/30"
                        : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                    }`}>
                    <span className="text-lg">{model.icon}</span>
                    <div className="flex-1 text-right">
                      <span className={`font-bold block ${model.color}`}>{model.name}</span>
                      {model.desc && <span className="text-[10px] text-muted-foreground">{model.desc}</span>}
                    </div>
                    {selectedModel === model.id && <CheckCircle2 className="w-4 h-4 text-primary shrink-0" />}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Language Switcher */}
          <LanguageSwitcher />

          <div className="w-px h-5 bg-border mx-1" />

          <Link href="/agent" className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/10 hover:bg-emerald-600/20 text-emerald-500 hover:text-emerald-400 transition-colors border border-emerald-600/20">
            <Terminal className="size-3.5" />
            <span className="text-xs font-bold">Code Agent</span>
          </Link>
        </div>

        {/* Messages */}
        <div ref={scrollRef} className="flex-1 overflow-y-auto scroll-smooth">
          <div className="max-w-3xl mx-auto py-6 px-4">
            {displayMessages.length === 0 && !isAiLoading && (
              <div className="text-center py-20">
                <img src={HAYO_LOGO} alt="HAYO AI" className="w-20 h-20 rounded-2xl mx-auto mb-6 shadow-lg shadow-indigo-500/25" />
                <h2 className="text-2xl font-heading font-bold mb-3">{t("chat.welcomeTitle")}</h2>
                <p className="text-muted-foreground mb-8 max-w-md mx-auto">
                  {t("chat.welcomeDesc")}
                </p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-lg mx-auto">
                  {[
                    { text: t("chat.suggestPython"), icon: Terminal, color: "text-emerald-500" },
                    { text: t("chat.suggestSearch"), icon: Globe, color: "text-amber-500" },
                    { text: t("chat.suggestCSV"), icon: Download, color: "text-indigo-500" },
                    { text: t("chat.suggestImage"), icon: ImageIcon, color: "text-purple-500" },
                  ].map(({ text, icon: Icon, color }) => (
                    <button
                      key={text}
                      onClick={() => { setInput(text); }}
                      className="flex items-center gap-3 p-3 rounded-xl border border-border bg-card hover:bg-accent/50 text-right text-sm transition-colors group"
                    >
                      <div className={cn("w-8 h-8 rounded-lg bg-accent/50 flex items-center justify-center shrink-0 group-hover:scale-110 transition-transform", color)}>
                        <Icon className="size-4" />
                      </div>
                      <span className="text-muted-foreground group-hover:text-foreground transition-colors">{text}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {displayMessages.map((msg, i) => (
              <div key={i} className={cn("mb-6", msg.role === "user" ? "flex justify-end" : "")}>
                {msg.role === "user" ? (
                  <div className="max-w-[85%]">
                    {msg.attachments && msg.attachments.length > 0 && (
                      <div className="flex flex-wrap gap-2 mb-2 justify-end">
                        {msg.attachments.map((att, j) => (
                          <div key={j} className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border bg-card text-xs">
                            {att.preview ? (
                              <img src={att.preview} alt={att.name} className="w-8 h-8 rounded object-cover" />
                            ) : getFileIcon(att.type)}
                            <div>
                              <div className="font-medium truncate max-w-[150px]">{att.name}</div>
                              <div className="text-muted-foreground">{formatFileSize(att.size)}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    <div className="bg-gradient-to-r from-indigo-500 to-violet-600 text-white px-4 py-3 rounded-2xl rounded-br-md">
                      <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
                    </div>
                  </div>
                ) : (
                  <div className="max-w-[95%]">
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center shrink-0 mt-1">
                        <Bot className="size-4 text-white" />
                      </div>
                      <div className="flex-1 min-w-0">
                        {msg.steps && msg.steps.length > 0 && (
                          <AgentStepsDisplay steps={msg.steps} />
                        )}
                        <div className="prose prose-invert prose-sm max-w-none
                          prose-headings:font-heading prose-headings:text-foreground
                          prose-p:text-foreground/90 prose-p:leading-relaxed
                          prose-a:text-primary prose-a:no-underline hover:prose-a:underline
                          prose-code:bg-accent/50 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-xs
                          prose-pre:bg-accent/30 prose-pre:border prose-pre:border-border prose-pre:rounded-xl
                          prose-img:rounded-xl prose-img:border prose-img:border-border prose-img:max-w-md
                          prose-strong:text-foreground prose-strong:font-semibold
                          prose-li:text-foreground/90
                        ">
                          <Streamdown>{msg.content}</Streamdown>
                        </div>
                        <div className="flex items-center gap-1 mt-2">
                          <CopyButton text={msg.content} />
                          <button onClick={() => speakText(msg.content)} className="p-1 rounded hover:bg-accent/50 text-muted-foreground hover:text-foreground transition-colors" title="قراءة صوتية">
                            {isSpeaking ? <VolumeX className="size-3.5 text-red-400" /> : <Volume2 className="size-3.5" />}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}

            {isAiLoading && <LoadingProgress />}
            <div ref={messagesEndRef} />
          </div>
        </div>

        {/* Drag overlay */}
        {isDragging && (
          <div className="absolute inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center">
            <div className="text-center p-8 rounded-2xl border-2 border-dashed border-primary bg-primary/5">
              <Paperclip className="size-12 text-primary mx-auto mb-3" />
              <p className="text-lg font-heading font-semibold">{t("chat.dropFilesHere")}</p>
              <p className="text-sm text-muted-foreground mt-1">{t("chat.dropFilesDesc")}</p>
            </div>
          </div>
        )}

        {/* Pending Files Preview */}
        {pendingFiles.length > 0 && (
          <div className="px-4 py-2 border-t border-border bg-card/50 shrink-0">
            <div className="max-w-3xl mx-auto flex flex-wrap gap-2">
              {pendingFiles.map((file, i) => (
                <div key={i} className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border bg-card text-xs group">
                  {file.preview ? (
                    <img src={file.preview} alt={file.name} className="w-6 h-6 rounded object-cover" />
                  ) : getFileIcon(file.type)}
                  <span className="truncate max-w-[120px]">{file.name}</span>
                  <button onClick={() => removePendingFile(i)} className="text-muted-foreground hover:text-destructive">
                    <X className="size-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Input Area */}
        <div className="border-t border-border bg-card/50 p-4 shrink-0">
          <div className="max-w-3xl mx-auto">
            <div className="flex items-end gap-2 rounded-xl border border-border bg-card p-2 focus-within:border-primary/50 transition-colors">
              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="hidden"
                accept="image/*,video/*,audio/*,.pdf,.doc,.docx,.txt,.csv,.json,.py,.js,.ts,.html,.css,.xml,.md,.xlsx,.xls,.zip,.rar,.7z,.tar,.gz,.pptx,.ppt,.svg,.sql,.yaml,.yml,.toml,.env,.sh,.bat,.ps1,.rb,.php,.java,.cpp,.c,.h,.hpp,.go,.rs,.swift,.kt,.dart,.lua,.r,.m,.mq4,.mq5,.mqh,.ex4,.ex5,.mp3,.wav,.ogg,.mp4,.webm,.mov"
                onChange={(e) => e.target.files && handleFileSelect(e.target.files)}
              />
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="shrink-0 size-9 text-muted-foreground hover:text-primary"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    <Paperclip className="size-5" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{t("chat.attachFile")}</TooltipContent>
              </Tooltip>

              {/* Voice Input */}
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button type="button" variant="ghost" size="icon" onClick={toggleRecording}
                    className={cn("shrink-0 size-9", isRecording ? "text-red-400 animate-pulse bg-red-500/10" : "text-muted-foreground hover:text-primary")}>
                    {isRecording ? <MicOff className="size-5" /> : <Mic className="size-5" />}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{isRecording ? "إيقاف التسجيل" : "تسجيل صوتي"}</TooltipContent>
              </Tooltip>

              {/* Image Generation */}
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button type="button" variant="ghost" size="icon" onClick={() => setShowImageGen(!showImageGen)}
                    className={cn("shrink-0 size-9", showImageGen ? "text-pink-400 bg-pink-500/10" : "text-muted-foreground hover:text-primary")}>
                    <ImagePlus className="size-5" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{t("chat.generateImage") || "توليد صورة AI"}</TooltipContent>
              </Tooltip>

              {/* Video Generation — Owner Only */}
              {isOwnerUser && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button type="button" variant="ghost" size="icon" onClick={() => setShowVideoGen(!showVideoGen)}
                      className={cn("shrink-0 size-9", showVideoGen ? "text-violet-400 bg-violet-500/10" : "text-muted-foreground hover:text-primary")}>
                      <Video className="size-5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{t("chat.generateVideo") || "🎬 توليد فيديو AI (حصري)"}</TooltipContent>
                </Tooltip>
              )}

              <textarea
                ref={textareaRef}
                value={input}
                onChange={handleInputChange}
                onKeyDown={handleKeyDown}
                placeholder={t("chat.placeholder")}
                className="flex-1 border-0 bg-transparent resize-none min-h-[40px] max-h-32 focus:outline-none focus:ring-0 p-1 text-sm placeholder:text-muted-foreground"
                rows={1}
                style={{ fieldSizing: "content" } as any}
              />

              <Button
                onClick={handleSend}
                disabled={(!input.trim() && pendingFiles.length === 0) || isAiLoading || (!!(user?.role !== "admin") && !!limitQuery.data?.isLimited)}
                size="icon"
                className="shrink-0 size-9 bg-gradient-to-r from-indigo-500 to-violet-600 hover:from-indigo-600 hover:to-violet-700 text-white disabled:opacity-40"
              >
                {isAiLoading ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
              </Button>
            </div>

            {/* Image Generation Panel */}
            {showImageGen && (
              <div className="bg-pink-500/5 border border-pink-500/20 rounded-xl p-3 flex items-center gap-3">
                <ImagePlus className="size-5 text-pink-400 shrink-0" />
                <input value={imagePrompt} onChange={e => setImagePrompt(e.target.value)} placeholder={t("chat.imagePromptPlaceholder") || "صف الصورة المطلوبة..."}
                  className="flex-1 bg-transparent border-0 text-sm focus:outline-none placeholder:text-muted-foreground/50"
                  onKeyDown={e => { if (e.key === "Enter") handleGenerateImage(); }} />
                <Button size="sm" onClick={handleGenerateImage} disabled={generatingImage || !imagePrompt.trim()} className="bg-pink-600 hover:bg-pink-700 text-white gap-1 text-xs">
                  {generatingImage ? <Loader2 className="size-3 animate-spin" /> : <ImagePlus className="size-3" />}
                  {generatingImage ? t("common.generating") || "يولّد..." : t("chat.createImage") || "إنشاء صورة"}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setShowImageGen(false)} className="size-7 p-0"><X className="size-3" /></Button>
              </div>
            )}

            {/* Video Generation Panel — Owner Only */}
            {showVideoGen && isOwnerUser && (
              <div className="bg-violet-500/5 border border-violet-500/20 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Video className="size-5 text-violet-400" />
                    <span className="text-sm font-bold text-violet-400">{t("chat.videoTitle") || "🎬 توليد فيديو AI"}</span>
                    <span className="text-[9px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400">{t("common.ownerBadge") || "👑 حصري"}</span>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => setShowVideoGen(false)} className="size-7 p-0"><X className="size-3" /></Button>
                </div>

                <textarea value={videoPrompt} onChange={e => setVideoPrompt(e.target.value)} rows={2}
                  placeholder={t("chat.videoPromptPlaceholder") || "صف المشهد بالتفصيل... مثال: طائر فينيق ينهض من النار في غابة مظلمة، إضاءة سينمائية، حركة بطيئة"}
                  className="w-full bg-card border border-border rounded-lg px-3 py-2 text-sm resize-none focus:ring-2 focus:ring-violet-500/50" />

                <div className="flex items-center gap-3">
                  {/* Model Selection */}
                  <div className="flex-1">
                    <label className="text-[10px] text-muted-foreground mb-1 block">{t("chat.videoModel") || "النموذج"}</label>
                    <div className="flex gap-1">
                      {[
                        { id: "minimax", label: "Minimax", emoji: "🎥" },
                        { id: "luma", label: "Luma Ray", emoji: "🎬" },
                        { id: "kling", label: "Kling", emoji: "🎞️" },
                        { id: "animate-diff", label: "AnimateDiff", emoji: "✨" },
                      ].map(m => (
                        <button key={m.id} onClick={() => setVideoModel(m.id)}
                          className={cn("px-2 py-1 rounded-lg text-[10px] border", videoModel === m.id ? "bg-violet-500/15 border-violet-500/40 text-violet-300" : "border-border text-muted-foreground")}>
                          {m.emoji} {m.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Aspect Ratio */}
                  <div>
                    <label className="text-[10px] text-muted-foreground mb-1 block">{t("chat.videoAspect") || "الأبعاد"}</label>
                    <div className="flex gap-1">
                      {["16:9", "9:16", "1:1"].map(ar => (
                        <button key={ar} onClick={() => setVideoAspect(ar)}
                          className={cn("px-2 py-1 rounded-lg text-[10px] border", videoAspect === ar ? "bg-violet-500/15 border-violet-500/40 text-violet-300" : "border-border text-muted-foreground")}>
                          {ar === "16:9" ? "🖥️" : ar === "9:16" ? "📱" : "⬛"} {ar}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                <Button onClick={handleGenerateVideo} disabled={generatingVideo || !videoPrompt.trim()} className="w-full gap-2 bg-gradient-to-r from-violet-600 to-purple-600 text-white">
                  {generatingVideo ? (
                    <><Loader2 className="size-4 animate-spin" /> {t("chat.generatingVideo") || "جاري التوليد (2-5 دقائق)..."}</>
                  ) : (
                    <><Video className="size-4" /> {t("chat.createVideo") || "إنشاء فيديو AI"}</>
                  )}
                </Button>

                {generatingVideo && (
                  <div className="bg-violet-500/10 rounded-lg p-2 text-[10px] text-violet-300 text-center animate-pulse">
                    ⏳ {t("chat.videoWait") || "توليد الفيديو يستغرق 2-5 دقائق... لا تغلق الصفحة"}
                  </div>
                )}
              </div>
            )}

            {/* Usage limit warning — hidden for owner */}
            {user?.role !== "admin" && limitQuery.data?.isLimited && (
              <div className="mt-3 p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="size-4 text-amber-400 shrink-0" />
                  <div>
                    <p className="text-xs font-medium text-amber-300">
                      وصلت إلى حد {limitQuery.data.dailyLimit} رسالة يومية مجانية
                    </p>
                    <p className="text-[10px] text-gray-400">اشترك لرفع الحد وإرسال رسائل غير محدودة</p>
                  </div>
                </div>
                <Link href="/payment?plan=basic">
                  <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-white text-xs font-semibold whitespace-nowrap transition-all">
                    <Crown className="size-3" />
                    اشترك الآن
                  </button>
                </Link>
              </div>
            )}

            {/* Usage counter (when approaching limit) */}
            {limitQuery.data && !limitQuery.data.isLimited && limitQuery.data.dailyLimit !== -1 && (
              (() => {
                const remaining = limitQuery.data.dailyLimit - limitQuery.data.todayCount;
                const pct = limitQuery.data.todayCount / limitQuery.data.dailyLimit;
                if (pct < 0.6) return null;
                return (
                  <p className="text-[10px] text-amber-400/70 text-center mt-1">
                    ⚡ {remaining} رسالة متبقية من أصل {limitQuery.data.dailyLimit} اليوم
                    {pct >= 0.8 && (
                      <Link href="/payment?plan=basic">
                        <span className="text-indigo-400 mr-1 hover:underline cursor-pointer">— اشترك لرفع الحد</span>
                      </Link>
                    )}
                  </p>
                );
              })()
            )}

            <p className="text-[10px] text-muted-foreground text-center mt-2">
              HAYO AI AGENT - {t("chat.footerDesc")}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
