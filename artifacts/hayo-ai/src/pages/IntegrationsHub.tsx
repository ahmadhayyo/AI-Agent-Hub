/**
 * HAYO AI - Integrations Hub v4.0
 * REAL integrations with backend API testing, database persistence,
 * visual icons, status indicators, and categorized services
 */

import { useState, useEffect, useMemo } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { trpc } from "@/lib/trpc";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import {
  CheckCircle2, AlertCircle, Unlink, Link as LinkIcon,
  Loader2, Eye, EyeOff, Home, MessageSquare, Terminal,
  ArrowLeft, Shield, Search, ExternalLink, Zap, Cloud,
  Database, Code2, Bot, Globe, Lock, Plug, Settings,
  Webhook, Send, HardDrive, Palette, FileCode, Cpu, Layers,
  RefreshCw, X,
} from "lucide-react";

// Logo
const HAYO_LOGO = import.meta.env.VITE_APP_LOGO || "";

// ─── Integration Definition (UI only) ───────────────────────────────
interface IntegrationDef {
  id: string;
  name: string;
  descKey: string;
  category: "ai" | "cloud" | "deploy" | "productivity" | "communication" | "database" | "trading" | "google" | "payments" | "appbuilding";
  iconColor: string;
  bgGradient: string;
  features: string[];
  docsUrl?: string;
  placeholder: string; // API key placeholder
}

// ─── Category Definitions ────────────────────────────────────────────
const CATEGORY_KEYS: Record<string, string> = {
  all: "integrations.categories.all",
  ai: "integrations.categories.ai",
  trading: "تداول مالي",
  communication: "integrations.categories.communication",
  google: "خدمات Google",
  deploy: "integrations.categories.deploy",
  payments: "مدفوعات",
  appbuilding: "بناء تطبيقات",
  cloud: "integrations.categories.cloud",
  database: "integrations.categories.database",
  productivity: "integrations.categories.productivity",
};

const CATEGORIES = [
  { id: "all", icon: Layers },
  { id: "ai", icon: Bot },
  { id: "trading", icon: Zap },
  { id: "communication", icon: Send },
  { id: "google", icon: Globe },
  { id: "deploy", icon: Globe },
  { id: "payments", icon: Shield },
  { id: "appbuilding", icon: Code2 },
  { id: "cloud", icon: Cloud },
  { id: "database", icon: Database },
  { id: "productivity", icon: Zap },
];

// ─── SVG Icons for Services ──────────────────────────────────────────
function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

function GoogleDriveIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className}>
      <path d="M7.71 3.5L1.15 15l3.43 5.96h6.86L7.71 3.5z" fill="#0066DA" />
      <path d="M16.29 3.5H9.43l6.56 11.5h6.86L16.29 3.5z" fill="#00AC47" />
      <path d="M1.15 15l3.43 5.96L8.01 15l-3.43-5.96L1.15 15z" fill="#EA4335" />
      <path d="M15.99 15h6.86l-3.43 5.96H12.56L15.99 15z" fill="#00832D" />
      <path d="M8.01 15l3.43 5.96h1.12L15.99 15H8.01z" fill="#2684FC" />
      <path d="M9.43 3.5l3.14 5.5 3.42-5.5H9.43z" fill="#FFBA00" />
    </svg>
  );
}

function VercelIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor">
      <path d="M12 1L24 22H0L12 1z" />
    </svg>
  );
}

function NotionIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor">
      <path d="M4.459 4.208c.746.606 1.026.56 2.428.466l13.215-.793c.28 0 .047-.28-.046-.326L18.26 2.23c-.42-.326-.98-.7-2.055-.607L3.01 2.75c-.466.046-.56.28-.373.466l1.822.992zm.793 3.08v13.904c0 .747.373 1.027 1.214.98l14.523-.84c.84-.046.933-.56.933-1.167V6.354c0-.606-.233-.933-.746-.886l-15.177.84c-.56.047-.747.327-.747.98zm14.337.745c.093.42 0 .84-.42.886l-.7.14v10.264c-.607.327-1.167.514-1.634.514-.746 0-.933-.234-1.493-.933l-4.572-7.186v6.953l1.447.327s0 .84-1.167.84l-3.22.186c-.093-.186 0-.653.327-.746l.84-.233V9.854L7.822 9.76c-.093-.42.14-1.026.793-1.073l3.453-.233 4.759 7.279V9.107l-1.213-.14c-.093-.514.28-.886.746-.933l3.22-.186z" />
    </svg>
  );
}

function AWSS3Icon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className}>
      <path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" fill="#FF9900" />
      <path d="M12 2L3 7l9 5 9-5-9-5z" fill="#FFB84D" />
      <path d="M12 12l-9-5v10l9 5V12z" fill="#FF9900" />
      <path d="M12 12l9-5v10l-9 5V12z" fill="#E68A00" />
      <text x="8" y="16" fill="white" fontSize="6" fontWeight="bold">S3</text>
    </svg>
  );
}

function SlackIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className}>
      <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313z" fill="#E01E5A" />
      <path d="M8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312z" fill="#36C5F0" />
      <path d="M18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312z" fill="#2EB67D" />
      <path d="M15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z" fill="#ECB22E" />
    </svg>
  );
}

function DiscordIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="#5865F2">
      <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
    </svg>
  );
}

function TelegramIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="#26A5E4">
      <path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z" />
    </svg>
  );
}

function OpenAIIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor">
      <path d="M22.282 9.821a5.985 5.985 0 0 0-.516-4.91 6.046 6.046 0 0 0-6.51-2.9A6.065 6.065 0 0 0 4.981 4.18a5.985 5.985 0 0 0-3.998 2.9 6.046 6.046 0 0 0 .743 7.097 5.98 5.98 0 0 0 .51 4.911 6.051 6.051 0 0 0 6.515 2.9A5.985 5.985 0 0 0 13.26 24a6.056 6.056 0 0 0 5.772-4.206 5.99 5.99 0 0 0 3.997-2.9 6.056 6.056 0 0 0-.747-7.073zM13.26 22.43a4.476 4.476 0 0 1-2.876-1.04l.141-.081 4.779-2.758a.795.795 0 0 0 .392-.681v-6.737l2.02 1.168a.071.071 0 0 1 .038.052v5.583a4.504 4.504 0 0 1-4.494 4.494zM3.6 18.304a4.47 4.47 0 0 1-.535-3.014l.142.085 4.783 2.759a.771.771 0 0 0 .78 0l5.843-3.369v2.332a.08.08 0 0 1-.033.062L9.74 19.95a4.5 4.5 0 0 1-6.14-1.646zM2.34 7.896a4.485 4.485 0 0 1 2.366-1.973V11.6a.766.766 0 0 0 .388.676l5.815 3.355-2.02 1.168a.076.076 0 0 1-.071 0l-4.83-2.786A4.504 4.504 0 0 1 2.34 7.872zm16.597 3.855l-5.833-3.387L15.119 7.2a.076.076 0 0 1 .071 0l4.83 2.791a4.494 4.494 0 0 1-.676 8.105v-5.678a.79.79 0 0 0-.407-.667zm2.01-3.023l-.141-.085-4.774-2.782a.776.776 0 0 0-.785 0L9.409 9.23V6.897a.066.066 0 0 1 .028-.061l4.83-2.787a4.5 4.5 0 0 1 6.68 4.66zm-12.64 4.135l-2.02-1.164a.08.08 0 0 1-.038-.057V6.075a4.5 4.5 0 0 1 7.375-3.453l-.142.08L8.704 5.46a.795.795 0 0 0-.393.681zm1.097-2.365l2.602-1.5 2.607 1.5v2.999l-2.597 1.5-2.607-1.5z" />
    </svg>
  );
}

function AnthropicIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor">
      <path d="M13.827 3.52h3.603L24 20.48h-3.603l-6.57-16.96zm-7.258 0h3.767L16.906 20.48h-3.674l-1.343-3.461H5.017l-1.344 3.46H0L6.57 3.522zm1.04 3.879L5.2 13.796h4.82l-2.41-6.397z" />
    </svg>
  );
}

function DeepSeekIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor">
      <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <path d="M8 12c0-2.2 1.8-4 4-4s4 1.8 4 4-1.8 4-4 4-4-1.8-4-4z" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="12" cy="12" r="1.5" />
    </svg>
  );
}

function GeminiIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className}>
      <path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12c2.8 0 5.4-1 7.4-2.6L12 12V0z" fill="#8E75B2" />
      <path d="M12 0v12l7.4 9.4C22 18.4 24 15.4 24 12 24 5.4 18.6 0 12 0z" fill="#4285F4" />
    </svg>
  );
}

function SupabaseIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className}>
      <path d="M13.7 21.8c-.4.5-1.3.2-1.3-.5V13h8.3c.8 0 1.2.9.7 1.5L13.7 21.8z" fill="#3ECF8E" />
      <path d="M13.7 21.8c-.4.5-1.3.2-1.3-.5V13h8.3c.8 0 1.2.9.7 1.5L13.7 21.8z" fill="url(#supabase-a)" fillOpacity=".2" />
      <path d="M10.3 2.2c.4-.5 1.3-.2 1.3.5V11H3.3c-.8 0-1.2-.9-.7-1.5L10.3 2.2z" fill="#3ECF8E" />
      <defs><linearGradient id="supabase-a" x1="12.4" y1="14.1" x2="17.3" y2="18.4" gradientUnits="userSpaceOnUse"><stop stopColor="#249361" /><stop offset="1" stopColor="#3ECF8E" /></linearGradient></defs>
    </svg>
  );
}

function FirebaseIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className}>
      <path d="M3.89 15.672L6.255 2.867a.39.39 0 01.727-.112l2.478 4.632L3.89 15.672z" fill="#FFA000" />
      <path d="M19.665 18.094L17.61 4.252a.39.39 0 00-.67-.196L3.89 15.672l6.95 3.9a1.17 1.17 0 001.137 0l7.688-1.478z" fill="#F57C00" />
      <path d="M10.867 9.958L9.46 7.387 3.89 15.672l6.977-5.714z" fill="#FFCA28" />
      <path d="M19.665 18.094l-2.055-13.842a.39.39 0 00-.67-.196L3.89 15.672l6.95 3.9a1.17 1.17 0 001.137 0l7.688-1.478z" fill="#FFA000" />
    </svg>
  );
}

function NetlifyIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor">
      <path d="M16.934 8.519a1.044 1.044 0 01.303.23l2.349-1.045-.001-.074a1.07 1.07 0 00-.472-.9l-6.27-3.57a1.07 1.07 0 00-1.07 0L5.503 6.73a1.07 1.07 0 00-.535.926v7.14a1.07 1.07 0 00.535.927l6.27 3.57a1.07 1.07 0 001.07 0l6.27-3.57a1.07 1.07 0 00.535-.927v-5.04l-2.349 1.046a1.044 1.044 0 01-.303.23l.001.07v3.247l-4.918 2.8-4.918-2.8V9.1l4.918-2.8 3.485 1.984z" fill="#00C7B7" />
    </svg>
  );
}

function GroqIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor">
      <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <text x="6" y="16" fontSize="10" fontWeight="bold" fill="currentColor">G</text>
    </svg>
  );
}

// ─── Icon Renderer ───────────────────────────────────────────────────
function IntegrationIcon({ id, className }: { id: string; className?: string }) {
  const cn = className || "w-8 h-8";
  switch (id) {
    case "github": return <GitHubIcon className={cn} />;
    case "google-drive": return <GoogleDriveIcon className={cn} />;
    case "vercel": return <VercelIcon className={cn} />;
    case "notion": return <NotionIcon className={cn} />;
    case "aws-s3": return <AWSS3Icon className={cn} />;
    case "slack": return <SlackIcon className={cn} />;
    case "discord": return <DiscordIcon className={cn} />;
    case "telegram": return <TelegramIcon className={cn} />;
    case "openai": return <OpenAIIcon className={cn} />;
    case "anthropic": return <AnthropicIcon className={cn} />;
    case "deepseek": return <DeepSeekIcon className={cn} />;
    case "gemini": return <GeminiIcon className={cn} />;
    case "groq": return <GroqIcon className={cn} />;
    case "supabase": return <SupabaseIcon className={cn} />;
    case "firebase": return <FirebaseIcon className={cn} />;
    case "netlify": return <NetlifyIcon className={cn} />;
    default: return <Plug className={cn} />;
  }
}

// ─── Integration Definitions ─────────────────────────────────────────
const INTEGRATION_DEFS: IntegrationDef[] = [
  // ═══ AI Models ═══
  { id: "anthropic", name: "Claude (Anthropic)", descKey: "integrations.services.anthropic", category: "ai",
    iconColor: "text-orange-400", bgGradient: "from-orange-500/20 to-amber-500/20",
    features: ["Claude Opus", "Sonnet", "Haiku", "Vision"], docsUrl: "https://docs.anthropic.com",
    placeholder: "sk-ant-..." },
  { id: "openai", name: "OpenAI", descKey: "integrations.services.openai", category: "ai",
    iconColor: "text-emerald-400", bgGradient: "from-emerald-500/20 to-green-500/20",
    features: ["GPT-4o", "DALL-E 3", "Whisper"], docsUrl: "https://platform.openai.com/docs",
    placeholder: "sk-..." },
  { id: "deepseek", name: "DeepSeek", descKey: "integrations.services.deepseek", category: "ai",
    iconColor: "text-blue-400", bgGradient: "from-blue-500/20 to-indigo-500/20",
    features: ["DeepSeek R1", "Coder", "Reasoning"], docsUrl: "https://platform.deepseek.com/docs",
    placeholder: "sk-..." },
  { id: "gemini", name: "Google Gemini", descKey: "integrations.services.gemini", category: "ai",
    iconColor: "text-purple-400", bgGradient: "from-purple-500/20 to-blue-500/20",
    features: ["Gemini 2.5 Pro", "Flash", "Vision"], docsUrl: "https://ai.google.dev/docs",
    placeholder: "AIza..." },
  { id: "groq", name: "Groq", descKey: "integrations.services.groq", category: "ai",
    iconColor: "text-red-400", bgGradient: "from-red-500/20 to-orange-500/20",
    features: ["Llama 3.3", "Mixtral", "Ultra-fast"], docsUrl: "https://console.groq.com/docs",
    placeholder: "gsk_..." },
  { id: "replicate", name: "Replicate", descKey: "توليد صور وفيديو AI", category: "ai",
    iconColor: "text-pink-400", bgGradient: "from-pink-500/20 to-rose-500/20",
    features: ["Stable Diffusion", "Flux", "Video AI"], docsUrl: "https://replicate.com/docs",
    placeholder: "r8_..." },
  // ═══ Trading & Finance ═══
  { id: "twelvedata", name: "TwelveData", descKey: "بيانات الأسواق المالية الحية", category: "trading",
    iconColor: "text-blue-400", bgGradient: "from-blue-500/20 to-cyan-500/20",
    features: ["Forex", "Stocks", "Crypto", "Indicators"], docsUrl: "https://twelvedata.com/docs",
    placeholder: "API Key" },
  { id: "binance", name: "Binance", descKey: "تداول العملات الرقمية", category: "trading",
    iconColor: "text-yellow-400", bgGradient: "from-yellow-500/20 to-amber-500/20",
    features: ["Spot", "Futures", "Market Data"], docsUrl: "https://binance-docs.github.io/apidocs",
    placeholder: "API Key + Secret" },
  { id: "alpaca", name: "Alpaca Markets", descKey: "تداول الأسهم الأمريكية", category: "trading",
    iconColor: "text-emerald-400", bgGradient: "from-emerald-500/20 to-green-500/20",
    features: ["Stock Trading", "Paper Trading", "Data"], docsUrl: "https://docs.alpaca.markets",
    placeholder: "API Key" },
  { id: "tradingview", name: "TradingView", descKey: "رسوم بيانية وتحليل فني", category: "trading",
    iconColor: "text-blue-500", bgGradient: "from-blue-600/20 to-indigo-500/20",
    features: ["Charts", "Webhooks", "Alerts"], docsUrl: "https://www.tradingview.com/rest-api-spec",
    placeholder: "Webhook URL" },
  { id: "oanda", name: "OANDA", descKey: "تداول فوركس احترافي مع API رسمي", category: "trading",
    iconColor: "text-cyan-400", bgGradient: "from-cyan-500/20 to-blue-500/20",
    features: ["Forex Trading", "REST API v20", "Market Data", "Auto Execute"], docsUrl: "https://developer.oanda.com/rest-live-v20/introduction",
    placeholder: "API Token" },
  { id: "ibkr", name: "Interactive Brokers", descKey: "تداول كل الأسواق العالمية", category: "trading",
    iconColor: "text-red-400", bgGradient: "from-red-500/20 to-rose-500/20",
    features: ["Stocks", "Forex", "Options", "Futures"], docsUrl: "https://interactivebrokers.github.io/cpwebapi",
    placeholder: "Client Portal Token" },
  // ═══ Communication ═══
  { id: "telegram", name: "Telegram", descKey: "integrations.services.telegram", category: "communication",
    iconColor: "text-blue-400", bgGradient: "from-blue-500/20 to-cyan-500/20",
    features: ["Bot API", "Notifications", "Commands"], docsUrl: "https://core.telegram.org/bots/api",
    placeholder: "123456:ABC-DEF..." },
  { id: "whatsapp", name: "WhatsApp Business", descKey: "رسائل WhatsApp تلقائية", category: "communication",
    iconColor: "text-green-400", bgGradient: "from-green-500/20 to-emerald-500/20",
    features: ["Messages", "Templates", "Media"], docsUrl: "https://developers.facebook.com/docs/whatsapp",
    placeholder: "Access Token" },
  { id: "slack", name: "Slack", descKey: "integrations.services.slack", category: "communication",
    iconColor: "text-purple-400", bgGradient: "from-purple-500/20 to-pink-500/20",
    features: ["Webhooks", "Bot", "Channels"],
    placeholder: "xoxb-..." },
  { id: "discord", name: "Discord", descKey: "integrations.services.discord", category: "communication",
    iconColor: "text-indigo-400", bgGradient: "from-indigo-500/20 to-blue-500/20",
    features: ["Bot", "Webhooks", "Commands"],
    placeholder: "Bot Token" },
  { id: "twilio", name: "Twilio", descKey: "SMS ومكالمات صوتية", category: "communication",
    iconColor: "text-red-400", bgGradient: "from-red-500/20 to-pink-500/20",
    features: ["SMS", "Voice", "WhatsApp"], docsUrl: "https://www.twilio.com/docs",
    placeholder: "Account SID + Auth Token" },
  // ═══ Google Services ═══
  { id: "google-drive", name: "Google Drive", descKey: "تخزين ومشاركة ملفات", category: "google",
    iconColor: "text-yellow-400", bgGradient: "from-yellow-500/20 to-green-500/20",
    features: ["Storage", "Docs", "Sheets", "Slides"],
    placeholder: "OAuth token or API key" },
  { id: "google-sheets", name: "Google Sheets", descKey: "جداول بيانات سحابية", category: "google",
    iconColor: "text-green-400", bgGradient: "from-green-500/20 to-emerald-500/20",
    features: ["Read/Write", "Formulas", "Charts"], docsUrl: "https://developers.google.com/sheets",
    placeholder: "API Key" },
  { id: "gmail", name: "Gmail API", descKey: "إرسال واستقبال البريد", category: "google",
    iconColor: "text-red-400", bgGradient: "from-red-500/20 to-rose-500/20",
    features: ["Send", "Read", "Labels"], docsUrl: "https://developers.google.com/gmail",
    placeholder: "OAuth Client ID" },
  { id: "google-calendar", name: "Google Calendar", descKey: "مواعيد وأحداث", category: "google",
    iconColor: "text-blue-400", bgGradient: "from-blue-500/20 to-indigo-500/20",
    features: ["Events", "Reminders", "Scheduling"], docsUrl: "https://developers.google.com/calendar",
    placeholder: "API Key" },
  // ═══ Deploy & Hosting ═══
  { id: "github", name: "GitHub", descKey: "integrations.services.github", category: "deploy",
    iconColor: "text-foreground", bgGradient: "from-gray-500/20 to-gray-300/20",
    features: ["Repos", "Actions", "Pages"], docsUrl: "https://docs.github.com",
    placeholder: "ghp_..." },
  { id: "vercel", name: "Vercel", descKey: "integrations.services.vercel", category: "deploy",
    iconColor: "text-foreground", bgGradient: "from-gray-500/20 to-gray-300/20",
    features: ["Deploy", "Domains", "Edge"], docsUrl: "https://vercel.com/docs",
    placeholder: "Bearer token" },
  { id: "railway", name: "Railway", descKey: "نشر Backend وقواعد بيانات", category: "deploy",
    iconColor: "text-violet-400", bgGradient: "from-violet-500/20 to-purple-500/20",
    features: ["Deploy", "PostgreSQL", "Cron"], docsUrl: "https://docs.railway.app",
    placeholder: "API Token" },
  // ═══ Payments ═══
  { id: "paypal", name: "PayPal", descKey: "مدفوعات واستلام أموال", category: "payments",
    iconColor: "text-blue-400", bgGradient: "from-blue-500/20 to-indigo-500/20",
    features: ["Payments", "Subscriptions", "Payouts"], docsUrl: "https://developer.paypal.com/docs",
    placeholder: "Client ID + Secret" },
  { id: "stripe", name: "Stripe", descKey: "بوابة دفع إلكترونية", category: "payments",
    iconColor: "text-violet-400", bgGradient: "from-violet-500/20 to-purple-500/20",
    features: ["Payments", "Subscriptions", "Invoices"], docsUrl: "https://stripe.com/docs",
    placeholder: "sk_live_..." },
  // ═══ App Building ═══
  { id: "expo-eas", name: "Expo EAS", descKey: "بناء تطبيقات React Native", category: "appbuilding",
    iconColor: "text-foreground", bgGradient: "from-gray-500/20 to-indigo-500/20",
    features: ["Build APK", "OTA Updates", "Submit"], docsUrl: "https://docs.expo.dev/eas",
    placeholder: "Expo Token" },
  { id: "zapier", name: "Zapier", descKey: "أتمتة سير العمل", category: "appbuilding",
    iconColor: "text-orange-400", bgGradient: "from-orange-500/20 to-red-500/20",
    features: ["Triggers", "Actions", "5000+ Apps"], docsUrl: "https://zapier.com/developer",
    placeholder: "API Key" },
  // ═══ Cloud ═══
  { id: "aws-s3", name: "AWS S3", descKey: "تخزين سحابي", category: "cloud",
    iconColor: "text-orange-400", bgGradient: "from-orange-500/20 to-yellow-500/20",
    features: ["Storage", "CDN", "Backup"], docsUrl: "https://docs.aws.amazon.com/s3",
    placeholder: "AKIA..." },
  { id: "cloudflare", name: "Cloudflare", descKey: "CDN وحماية وDNS", category: "cloud",
    iconColor: "text-orange-400", bgGradient: "from-orange-500/20 to-amber-500/20",
    features: ["CDN", "DNS", "Workers", "R2"], docsUrl: "https://developers.cloudflare.com",
    placeholder: "API Token" },
  // ═══ Database ═══
  { id: "supabase", name: "Supabase", descKey: "integrations.services.supabase", category: "database",
    iconColor: "text-emerald-400", bgGradient: "from-emerald-500/20 to-green-500/20",
    features: ["PostgreSQL", "Auth", "Storage", "Realtime"], docsUrl: "https://supabase.com/docs",
    placeholder: "eyJ..." },
  { id: "firebase", name: "Firebase", descKey: "integrations.services.firebase", category: "database",
    iconColor: "text-amber-400", bgGradient: "from-amber-500/20 to-orange-500/20",
    features: ["Firestore", "Auth", "Hosting"], docsUrl: "https://firebase.google.com/docs",
    placeholder: "AIza..." },
  { id: "mongodb", name: "MongoDB Atlas", descKey: "قاعدة بيانات NoSQL", category: "database",
    iconColor: "text-green-400", bgGradient: "from-green-500/20 to-emerald-500/20",
    features: ["NoSQL", "Atlas Search", "Charts"], docsUrl: "https://www.mongodb.com/docs/atlas",
    placeholder: "mongodb+srv://..." },
  // ═══ Productivity ═══
  { id: "notion", name: "Notion", descKey: "integrations.services.notion", category: "productivity",
    iconColor: "text-foreground", bgGradient: "from-gray-500/20 to-gray-300/20",
    features: ["Docs", "Databases", "Wikis"], docsUrl: "https://developers.notion.com",
    placeholder: "ntn_..." },
  { id: "airtable", name: "Airtable", descKey: "جداول وقواعد بيانات مرنة", category: "productivity",
    iconColor: "text-blue-400", bgGradient: "from-blue-500/20 to-cyan-500/20",
    features: ["Tables", "Views", "Automations"], docsUrl: "https://airtable.com/developers/web",
    placeholder: "pat..." },
];

// ─── Credential field definitions per provider ───────────────────────
interface FieldDef { key: string; label: string; type: "text" | "password" | "textarea"; hint?: string; }
const CREDENTIAL_FIELDS: Record<string, FieldDef[]> = {
  // AI
  openai:       [{ key: "apiKey", label: "OpenAI API Key", type: "password", hint: "sk-..." }],
  anthropic:    [{ key: "apiKey", label: "Anthropic API Key", type: "password", hint: "sk-ant-..." }],
  deepseek:     [{ key: "apiKey", label: "DeepSeek API Key", type: "password", hint: "sk-..." }],
  gemini:       [{ key: "apiKey", label: "Gemini API Key", type: "password", hint: "AIza..." }],
  groq:         [{ key: "apiKey", label: "Groq API Key", type: "password", hint: "gsk_..." }],
  replicate:    [{ key: "apiKey", label: "Replicate API Token", type: "password", hint: "r8_..." }],
  // Trading
  twelvedata:   [{ key: "apiKey", label: "TwelveData API Key", type: "password" }],
  binance: [
    { key: "apiKey", label: "Binance API Key", type: "password" },
    { key: "secretKey", label: "Secret Key", type: "password" },
  ],
  alpaca: [
    { key: "apiKey", label: "Alpaca API Key", type: "password" },
    { key: "secretKey", label: "Secret Key", type: "password" },
    { key: "baseUrl", label: "Base URL", type: "text", hint: "https://paper-api.alpaca.markets" },
  ],
  tradingview:  [{ key: "webhookUrl", label: "Webhook URL", type: "text", hint: "https://..." }],
  oanda: [
    { key: "apiToken", label: "OANDA API Token", type: "password", hint: "Practice أو Live token" },
    { key: "accountId", label: "Account ID", type: "text", hint: "001-001-1234567-001" },
    { key: "environment", label: "Environment", type: "text", hint: "practice أو live" },
  ],
  ibkr: [
    { key: "token", label: "Client Portal Token", type: "password" },
    { key: "accountId", label: "Account ID", type: "text", hint: "U1234567" },
  ],
  // Communication
  telegram:     [{ key: "token", label: "Bot Token", type: "password", hint: "123456:ABC-DEF..." }],
  whatsapp: [
    { key: "phoneId", label: "Phone Number ID", type: "text" },
    { key: "token", label: "Access Token", type: "password" },
  ],
  slack:        [{ key: "token", label: "Bot Token", type: "password", hint: "xoxb-..." }],
  discord:      [{ key: "token", label: "Bot Token", type: "password" }],
  twilio: [
    { key: "accountSid", label: "Account SID", type: "text", hint: "AC..." },
    { key: "authToken", label: "Auth Token", type: "password" },
    { key: "phoneNumber", label: "Twilio Phone Number", type: "text", hint: "+1234567890" },
  ],
  // Google
  "google-drive": [
    { key: "clientId", label: "Client ID", type: "text", hint: "xxx.apps.googleusercontent.com" },
    { key: "clientSecret", label: "Client Secret", type: "password", hint: "GOCSPX-..." },
  ],
  "google-sheets": [{ key: "apiKey", label: "Google API Key", type: "password", hint: "AIza..." }],
  gmail: [
    { key: "clientId", label: "OAuth Client ID", type: "text" },
    { key: "clientSecret", label: "Client Secret", type: "password" },
  ],
  "google-calendar": [{ key: "apiKey", label: "Google API Key", type: "password", hint: "AIza..." }],
  // Deploy
  github:       [{ key: "token", label: "Personal Access Token", type: "password", hint: "ghp_..." }],
  vercel:       [{ key: "token", label: "Vercel Token", type: "password" }],
  railway:      [{ key: "token", label: "Railway API Token", type: "password" }],
  // Payments
  paypal: [
    { key: "clientId", label: "Client ID", type: "text" },
    { key: "clientSecret", label: "Client Secret", type: "password" },
    { key: "mode", label: "Mode", type: "text", hint: "sandbox or live" },
  ],
  stripe:       [{ key: "secretKey", label: "Secret Key", type: "password", hint: "sk_live_..." }],
  // App Building
  "expo-eas":   [{ key: "token", label: "Expo Access Token", type: "password" }],
  zapier:       [{ key: "apiKey", label: "Zapier API Key", type: "password" }],
  // Cloud
  "aws-s3": [
    { key: "accessKeyId", label: "Access Key ID", type: "text", hint: "AKIA..." },
    { key: "secretAccessKey", label: "Secret Access Key", type: "password" },
    { key: "region", label: "Region", type: "text", hint: "us-east-1" },
    { key: "bucket", label: "Bucket Name", type: "text", hint: "my-bucket" },
  ],
  cloudflare:   [{ key: "apiToken", label: "API Token", type: "password" }],
  // Database
  supabase: [
    { key: "url", label: "Supabase URL", type: "text", hint: "https://xxx.supabase.co" },
    { key: "apiKey", label: "Anon Key", type: "password", hint: "eyJ..." },
  ],
  firebase:     [{ key: "serviceAccount", label: "Service Account JSON", type: "textarea", hint: '{"type":"service_account",...}' }],
  mongodb:      [{ key: "connectionString", label: "Connection String", type: "password", hint: "mongodb+srv://..." }],
  // Productivity
  notion:       [{ key: "apiKey", label: "Notion API Key", type: "password", hint: "ntn_..." }],
  airtable:     [{ key: "apiKey", label: "Personal Access Token", type: "password", hint: "pat..." }],
};

// ─── Component ───────────────────────────────────────────────────────
export default function IntegrationsHub() {
  const { isAuthenticated, loading: authLoading } = useAuth();
  const { t } = useTranslation();
  const [, navigate] = useLocation();
  const [activeCategory, setActiveCategory] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [dialogProvider, setDialogProvider] = useState<string | null>(null);
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [showFields, setShowFields] = useState<Record<string, boolean>>({});
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; info?: any; error?: string } | null>(null);
  const [disconnecting, setDisconnecting] = useState<string | null>(null);

  // ─── Real tRPC calls ──────────────────────────────────────────────
  const utils = trpc.useUtils();
  const { data: savedIntegrations, isLoading: integrationsLoading } = trpc.integrations.list.useQuery(
    undefined, { enabled: isAuthenticated }
  );

  // Telegram uses a dedicated table — check it separately
  const { data: telegramBot } = trpc.telegram.getBot.useQuery(
    undefined, { enabled: isAuthenticated }
  );

  const testMutation = trpc.integrations.test.useMutation({
    onSuccess: (data: any) => {
      setTesting(false);
      setTestResult(data as any);
      if ((data as any).success) {
        toast.success("الاتصال ناجح! 🎉 يمكنك الآن حفظ التكامل.");
      } else {
        toast.error(`فشل الاتصال: ${(data as any).error}`);
      }
    },
    onError: (err: any) => { setTesting(false); toast.error(err.message); },
  });

  const connectMutation = trpc.integrations.connect.useMutation({
    onSuccess: (_data: any, variables: any) => {
      utils.integrations.list.invalidate();
      setDialogProvider(null);
      setCredentials({});
      setTestResult(null);
      const name = INTEGRATION_DEFS.find(i => i.id === variables.provider)?.name;
      toast.success(`✅ تم ربط ${name} بنجاح!`);
    },
    onError: (err: any) => toast.error(`فشل الاتصال: ${err.message}`),
  });

  const disconnectMutation = trpc.integrations.disconnect.useMutation({
    onSuccess: (_data: any, variables: any) => {
      utils.integrations.list.invalidate();
      setDisconnecting(null);
      const name = INTEGRATION_DEFS.find(i => i.id === variables.provider)?.name;
      toast.success(`تم فصل ${name}`);
    },
    onError: (err: any) => { setDisconnecting(null); toast.error(err.message); },
  });

  const telegramDisconnectMutation = trpc.telegram.disconnect.useMutation({
    onSuccess: () => {
      utils.telegram.getBot.invalidate();
      setDisconnecting(null);
      toast.success("تم فصل Telegram");
    },
    onError: (err: any) => { setDisconnecting(null); toast.error(err.message); },
  });

  // Build connected set from database
  const connectedSet = useMemo(() => {
    const set = new Set<string>();
    if (savedIntegrations) {
      for (const int of savedIntegrations as any[]) {
        if (int.isActive) set.add(int.provider);
      }
    }
    // Telegram has its own dedicated table
    if ((telegramBot as any)?.isActive) set.add("telegram");
    return set;
  }, [savedIntegrations, telegramBot]);

  const connectedInfo = useMemo(() => {
    const map = new Map<string, any>();
    if (savedIntegrations) {
      for (const int of savedIntegrations as any[]) {
        if (int.info) map.set(int.provider, int.info);
      }
    }
    // Telegram info from its dedicated table
    if ((telegramBot as any)?.isActive) {
      map.set("telegram", { "اسم البوت": `@${(telegramBot as any).botUsername || "—"}` });
    }
    return map;
  }, [savedIntegrations, telegramBot]);

  // Filter integrations
  const filtered = INTEGRATION_DEFS.filter(int => {
    const matchesCategory = activeCategory === "all" || int.category === activeCategory;
    const matchesSearch = int.name.toLowerCase().includes(searchQuery.toLowerCase()) || t(int.descKey).includes(searchQuery);
    return matchesCategory && matchesSearch;
  });

  const connectedCount = connectedSet.size;

  const openDialog = (id: string) => {
    // Telegram uses a dedicated page with full webhook setup
    if (id === "telegram") {
      navigate("/telegram");
      return;
    }
    setDialogProvider(id);
    setCredentials({});
    setShowFields({});
    setTestResult(null);
  };

  const handleTest = () => {
    if (!dialogProvider) return;
    const fields = CREDENTIAL_FIELDS[dialogProvider] || [];
    for (const f of fields) {
      if (!credentials[f.key]?.trim()) { toast.error(`يرجى إدخال ${f.label}`); return; }
    }
    setTesting(true);
    setTestResult(null);
    testMutation.mutate({ provider: dialogProvider, credentials });
  };

  const handleConnect = () => {
    if (!dialogProvider) return;
    connectMutation.mutate({ provider: dialogProvider, credentials });
  };

  const handleDisconnect = (id: string) => {
    setDisconnecting(id);
    if (id === "telegram") {
      telegramDisconnectMutation.mutate();
    } else {
      disconnectMutation.mutate({ provider: id });
    }
  };

  const dialogDef = INTEGRATION_DEFS.find(d => d.id === dialogProvider);
  const dialogFields = dialogProvider ? (CREDENTIAL_FIELDS[dialogProvider] || [{ key: "apiKey", label: "API Key", type: "password" as const }]) : [];

  if (authLoading || integrationsLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
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
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-xl sticky top-0 z-40">
        <div className="container flex items-center justify-between h-14">
          <div className="flex items-center gap-3">
            <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">
              <Home className="w-4 h-4" />
            </Link>
            <div className="w-px h-5 bg-border" />
            {HAYO_LOGO && <img src={HAYO_LOGO} alt="HAYO" className="w-6 h-6 rounded" />}
            <div>
              <h1 className="font-heading font-bold text-sm flex items-center gap-2">
                <Plug className="w-4 h-4 text-primary" /> {t("integrations.title")}
              </h1>
              <p className="text-[10px] text-muted-foreground">{t("integrations.subtitle")}</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 px-3 py-1 bg-secondary/50 rounded-lg text-xs">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-muted-foreground">{connectedCount} {t("integrations.connectedCount")}</span>
            </div>
            <Link href="/agent">
              <Button variant="outline" size="sm" className="text-xs gap-1">
                <Terminal className="w-3.5 h-3.5" /> {t("nav.agent")}
              </Button>
            </Link>
            <Link href="/chat">
              <Button variant="outline" size="sm" className="text-xs gap-1">
                <MessageSquare className="w-3.5 h-3.5" /> {t("nav.chat")}
              </Button>
            </Link>
          </div>
        </div>
      </header>

      <div className="container py-8 space-y-8">
        {/* Featured Telegram Integration */}
        {!connectedSet.has("telegram") && (
          <div className="bg-gradient-to-r from-[#26A5E4]/20 via-[#26A5E4]/10 to-transparent border border-[#26A5E4]/30 rounded-2xl p-6 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-16 h-16 rounded-2xl bg-[#26A5E4]/20 flex items-center justify-center shrink-0">
                <TelegramIcon className="w-10 h-10" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-foreground flex items-center gap-2">
                  🚀 تحدث مع الوكيل عبر Telegram
                </h3>
                <p className="text-sm text-muted-foreground mt-1">
                  اربط بوت Telegram الخاص بك والتحدث مع الوكيل الذكي مباشرة من Telegram
                </p>
              </div>
            </div>
            <Link href="/telegram">
              <Button className="bg-[#26A5E4] hover:bg-[#26A5E4]/80 text-white gap-2 whitespace-nowrap">
                <Plug className="w-4 h-4" />
                إعداد الآن
              </Button>
            </Link>
          </div>
        )}

        {/* Search + Categories */}
        <div className="space-y-4">
          <div className="relative max-w-md">
            <Search className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t("integrations.searchPlaceholder")}
              className="w-full pr-10 pl-4 py-2.5 bg-card border border-border rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 placeholder:text-muted-foreground/50"
            />
          </div>

          <div className="flex gap-2 overflow-x-auto pb-1">
            {CATEGORIES.map((cat) => {
              const Icon = cat.icon;
              const count = cat.id === "all" ? INTEGRATION_DEFS.length : INTEGRATION_DEFS.filter((i) => i.category === cat.id).length;
              return (
                <button key={cat.id} onClick={() => setActiveCategory(cat.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${activeCategory === cat.id ? "bg-primary/15 text-primary ring-1 ring-primary/30" : "bg-secondary/50 text-muted-foreground hover:text-foreground hover:bg-secondary"}`}>
                  <Icon className="w-3.5 h-3.5" />
                  {t(CATEGORY_KEYS[cat.id] || cat.id)}
                  <span className="text-[10px] opacity-60">({count})</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Connection Dialog */}
        {dialogProvider && dialogDef && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={() => setDialogProvider(null)}>
            <div className="bg-card border border-border rounded-2xl w-full max-w-md shadow-2xl" onClick={e => e.stopPropagation()}>
              {/* Dialog Header */}
              <div className="flex items-center justify-between p-5 border-b border-border">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-xl bg-background border border-border/50 flex items-center justify-center ${dialogDef.iconColor}`}>
                    <IntegrationIcon id={dialogProvider} className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="font-bold text-sm">ربط {dialogDef.name}</h3>
                    <p className="text-[10px] text-muted-foreground">أدخل بياناتك وقم باختبار الاتصال</p>
                  </div>
                </div>
                <button onClick={() => setDialogProvider(null)} className="p-1.5 rounded-lg hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors">
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Dialog Fields */}
              <div className="p-5 space-y-4">
                {dialogFields.map(field => (
                  <div key={field.key}>
                    <label className="text-xs font-medium text-muted-foreground block mb-1.5">{field.label}</label>
                    {field.type === "textarea" ? (
                      <textarea
                        rows={4}
                        value={credentials[field.key] || ""}
                        onChange={e => setCredentials(c => ({ ...c, [field.key]: e.target.value }))}
                        placeholder={field.hint || ""}
                        className="w-full px-3 py-2 text-xs border border-border rounded-lg bg-background resize-none focus:outline-none focus:ring-1 focus:ring-primary/50 placeholder:text-muted-foreground/40 font-mono"
                      />
                    ) : (
                      <div className="relative">
                        <input
                          type={showFields[field.key] ? "text" : field.type}
                          value={credentials[field.key] || ""}
                          onChange={e => setCredentials(c => ({ ...c, [field.key]: e.target.value }))}
                          placeholder={field.hint || ""}
                          className="w-full px-3 py-2 text-xs border border-border rounded-lg bg-background focus:outline-none focus:ring-1 focus:ring-primary/50 placeholder:text-muted-foreground/40 font-mono pr-8"
                        />
                        {field.type === "password" && (
                          <button
                            onClick={() => setShowFields(s => ({ ...s, [field.key]: !s[field.key] }))}
                            className="absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                            {showFields[field.key] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                ))}

                {dialogDef.docsUrl && (
                  <a href={dialogDef.docsUrl} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-1 text-xs text-primary hover:underline">
                    <ExternalLink className="w-3 h-3" /> الحصول على مفتاح API
                  </a>
                )}

                {/* Test Result */}
                {testResult && (
                  <div className={`p-3 rounded-xl border text-xs ${testResult.success ? "border-emerald-500/30 bg-emerald-500/10" : "border-red-500/30 bg-red-500/10"}`}>
                    {testResult.success ? (
                      <div className="space-y-1">
                        <p className="font-bold text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> الاتصال ناجح!
                        </p>
                        {testResult.info && Object.entries(testResult.info).map(([k, v]) => (
                          <p key={k} className="text-emerald-300">{k}: {String(v)}</p>
                        ))}
                      </div>
                    ) : (
                      <p className="text-red-400 flex items-center gap-1">
                        <AlertCircle className="w-3.5 h-3.5" /> {testResult.error}
                      </p>
                    )}
                  </div>
                )}

                {/* Actions */}
                <div className="flex gap-2 pt-1">
                  <Button size="sm" variant="outline" onClick={handleTest} disabled={testing || connectMutation.isPending}
                    className="flex-1 text-xs gap-1">
                    {testing ? <><Loader2 className="w-3 h-3 animate-spin" />اختبار...</> : <><Zap className="w-3 h-3" />اختبار الاتصال</>}
                  </Button>
                  <Button size="sm" onClick={handleConnect}
                    disabled={!testResult?.success || connectMutation.isPending}
                    className="flex-1 text-xs gap-1 bg-emerald-600 hover:bg-emerald-700">
                    {connectMutation.isPending ? <><Loader2 className="w-3 h-3 animate-spin" />حفظ...</> : <><LinkIcon className="w-3 h-3" />حفظ وربط</>}
                  </Button>
                </div>
                <p className="text-[10px] text-muted-foreground text-center">🔒 يتم تشفير جميع البيانات قبل الحفظ</p>
              </div>
            </div>
          </div>
        )}

        {/* Integration Cards Grid */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {filtered.map((def) => {
            const isConnected = connectedSet.has(def.id);
            const info = connectedInfo.get(def.id);

            return (
              <div key={def.id}
                className={`group relative bg-card border rounded-xl overflow-hidden transition-all duration-300 hover:shadow-lg hover:shadow-primary/5 ${isConnected ? "border-emerald-500/30" : "border-border hover:border-primary/30"}`}>
                <div className={`absolute inset-0 bg-gradient-to-br ${def.bgGradient} opacity-30 group-hover:opacity-50 transition-opacity`} />

                <div className="relative p-4 space-y-3">
                  {/* Icon + Status */}
                  <div className="flex items-start justify-between">
                    <div className={`w-12 h-12 rounded-xl bg-background/80 border border-border/50 flex items-center justify-center ${def.iconColor}`}>
                      <IntegrationIcon id={def.id} className="w-7 h-7" />
                    </div>
                    {isConnected ? (
                      <span className="flex items-center gap-1 text-[10px] font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full">
                        <CheckCircle2 className="w-3 h-3" /> متصل
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-[10px] font-bold text-muted-foreground bg-secondary/50 px-2 py-0.5 rounded-full">
                        <AlertCircle className="w-3 h-3" /> غير متصل
                      </span>
                    )}
                  </div>

                  {/* Name + Description */}
                  <div>
                    <h3 className="font-heading font-bold text-sm text-foreground">{def.name}</h3>
                    <p className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed">{t(def.descKey)}</p>
                  </div>

                  {/* Connected Info */}
                  {isConnected && info && Object.keys(info).length > 0 && (
                    <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-2 space-y-0.5">
                      {Object.entries(info).slice(0, 3).map(([k, v]) => (
                        <p key={k} className="text-[10px] text-emerald-400 flex items-center gap-1">
                          <span className="text-emerald-600">•</span>
                          <span className="font-medium">{k}:</span>
                          <span className="truncate">{String(v)}</span>
                        </p>
                      ))}
                    </div>
                  )}

                  {/* Features */}
                  <div className="flex flex-wrap gap-1">
                    {def.features.map((f, i) => (
                      <span key={i} className="text-[9px] px-1.5 py-0.5 bg-secondary/50 text-muted-foreground rounded">{f}</span>
                    ))}
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-2 pt-2 border-t border-border/50">
                    {isConnected ? (
                      <>
                        <Button size="sm" variant="outline"
                          className="flex-1 text-[10px] gap-1 text-red-400 border-red-400/30 hover:bg-red-400/10"
                          onClick={() => handleDisconnect(def.id)} disabled={disconnecting === def.id}>
                          {disconnecting === def.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Unlink className="w-3 h-3" />}
                          فصل
                        </Button>
                        <Button size="sm" variant="outline" className="flex-1 text-[10px] gap-1" onClick={() => openDialog(def.id)}>
                          <RefreshCw className="w-3 h-3" /> تحديث
                        </Button>
                      </>
                    ) : (
                      <Button size="sm" className="w-full text-xs gap-1 bg-primary/90 hover:bg-primary" onClick={() => openDialog(def.id)}>
                        <LinkIcon className="w-3 h-3" /> ربط الخدمة
                      </Button>
                    )}
                    {def.docsUrl && (
                      <a href={def.docsUrl} target="_blank" rel="noopener noreferrer">
                        <Button size="sm" variant="ghost" className="text-[10px] gap-1 px-2">
                          <ExternalLink className="w-3 h-3" />
                        </Button>
                      </a>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Empty State */}
        {filtered.length === 0 && (
          <div className="text-center py-16 space-y-3">
            <Search className="w-12 h-12 text-muted-foreground/30 mx-auto" />
            <p className="text-muted-foreground">{t("common.noResults")}</p>
          </div>
        )}

        {/* Security Notice */}
        <div className="bg-card border border-border rounded-xl p-5">
          <div className="flex items-start gap-3">
            <Shield className="w-5 h-5 text-emerald-400 mt-0.5 shrink-0" />
            <div>
              <h3 className="font-heading font-bold text-sm text-foreground mb-1">{t("integrations.securityNote")}</h3>
              <p className="text-xs text-muted-foreground leading-relaxed">
                {t("integrations.securityDesc")}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
