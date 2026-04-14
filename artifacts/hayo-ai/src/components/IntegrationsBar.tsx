import { useState } from "react";
import {
  Github, HardDrive, BookOpen, MessageSquare,
  Cloud, Database, Link2, ChevronDown, ChevronUp, ExternalLink,
} from "lucide-react";
import { toast } from "sonner";

const INTEGRATIONS = [
  {
    id: "github",
    name: "GitHub",
    icon: <Github className="w-3.5 h-3.5" />,
    desc: "اقرأ مستودعاتك",
  },
  {
    id: "google-drive",
    name: "Google Drive",
    icon: <HardDrive className="w-3.5 h-3.5" />,
    desc: "ملفاتك ومستنداتك",
  },
  {
    id: "notion",
    name: "Notion",
    icon: <BookOpen className="w-3.5 h-3.5" />,
    desc: "صفحاتك في Notion",
  },
  {
    id: "slack",
    name: "Slack",
    icon: <MessageSquare className="w-3.5 h-3.5" />,
    desc: "إرسال إشعارات",
  },
  {
    id: "discord",
    name: "Discord",
    icon: <MessageSquare className="w-3.5 h-3.5" />,
    desc: "ربط السيرفرات",
  },
  {
    id: "vercel",
    name: "Vercel",
    icon: <Cloud className="w-3.5 h-3.5" />,
    desc: "نشر تلقائي",
  },
  {
    id: "aws-s3",
    name: "AWS S3",
    icon: <Database className="w-3.5 h-3.5" />,
    desc: "تخزين الملفات",
  },
];

export default function IntegrationsBar() {
  const [expanded, setExpanded] = useState(false);

  function handleClick(name: string) {
    toast.info(`لربط ${name} أضف مفتاح API في إعدادات حسابك`, {
      action: {
        label: "الإعدادات",
        onClick: () => (window.location.href = "/account"),
      },
      duration: 4000,
    });
  }

  return (
    <div className="border-b border-border/40 bg-background/30 backdrop-blur-sm">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-1.5 hover:bg-white/3 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Link2 className="w-3 h-3 text-muted-foreground/60" />
          <span className="text-xs text-muted-foreground/60">ربط المنصات</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-0.5">
            {INTEGRATIONS.slice(0, 5).map((i) => (
              <div
                key={i.id}
                title={i.name}
                className="w-5 h-5 rounded flex items-center justify-center border text-muted-foreground/30 bg-white/3 border-white/5"
              >
                {i.icon}
              </div>
            ))}
            <span className="text-xs text-muted-foreground/30 px-1">
              +{INTEGRATIONS.length - 5}
            </span>
          </div>
          {expanded ? (
            <ChevronUp className="w-3 h-3 text-muted-foreground/40" />
          ) : (
            <ChevronDown className="w-3 h-3 text-muted-foreground/40" />
          )}
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-3 pt-1 grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2">
          {INTEGRATIONS.map((i) => (
            <button
              key={i.id}
              onClick={() => handleClick(i.name)}
              className="flex flex-col items-center gap-1.5 p-2.5 rounded-xl border border-white/8 bg-white/3 text-muted-foreground hover:border-white/15 hover:bg-white/5 transition-all group"
            >
              <div className="w-8 h-8 rounded-lg flex items-center justify-center border border-white/10 bg-white/5 group-hover:scale-110 transition-transform">
                {i.icon}
              </div>
              <span className="text-xs font-medium">{i.name}</span>
              <span className="text-xs opacity-50 text-center leading-tight">{i.desc}</span>
              <ExternalLink className="w-2.5 h-2.5 opacity-20" />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
