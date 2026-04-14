import { motion, AnimatePresence } from "framer-motion";
import { CheckCircle2, Clock, Copy, Download, Plus, ArrowRight, Sparkles, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { toast } from "sonner";

export interface CompletionStats {
  duration: string;
  steps: string[];
  tokensUsed?: number;
  filesCreated?: number;
  searchesRun?: number;
  codeExecuted?: number;
}

interface ProjectCompletionScreenProps {
  isOpen: boolean;
  title?: string;
  summary?: string;
  stats: CompletionStats;
  downloadUrl?: string;
  onClose: () => void;
  onNewTask: () => void;
  onContinue?: () => void;
}

export default function ProjectCompletionScreen({
  isOpen,
  title = "اكتملت المهمة بنجاح! 🎉",
  summary,
  stats,
  downloadUrl,
  onClose,
  onNewTask,
  onContinue,
}: ProjectCompletionScreenProps) {
  const [copied, setCopied] = useState(false);

  const handleCopySummary = () => {
    if (!summary) return;
    navigator.clipboard.writeText(summary);
    setCopied(true);
    toast.success("تم نسخ الملخص");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
          onClick={(e) => e.target === e.currentTarget && onClose()}
        >
          <motion.div
            initial={{ scale: 0.8, opacity: 0, y: 40 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.9, opacity: 0, y: 20 }}
            transition={{ type: "spring", damping: 20, stiffness: 300 }}
            className="bg-background border border-border rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden"
          >
            <div className="relative bg-gradient-to-br from-green-500/10 via-emerald-500/5 to-background p-8 text-center border-b border-border">
              <button
                onClick={onClose}
                className="absolute top-4 right-4 text-muted-foreground hover:text-foreground transition-colors"
              >
                <X className="w-5 h-5" />
              </button>

              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", damping: 12, stiffness: 200, delay: 0.1 }}
                className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-green-500/10 border-2 border-green-500 mb-4 mx-auto"
              >
                <motion.div
                  initial={{ pathLength: 0 }}
                  animate={{ pathLength: 1 }}
                  transition={{ duration: 0.5, delay: 0.3 }}
                >
                  <CheckCircle2 className="w-10 h-10 text-green-500" />
                </motion.div>
              </motion.div>

              <motion.h2
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="text-xl font-bold mb-2"
              >
                {title}
              </motion.h2>

              {summary && (
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.3 }}
                  className="text-muted-foreground text-sm leading-relaxed"
                >
                  {summary}
                </motion.p>
              )}
            </div>

            <div className="p-6 space-y-4">
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.35 }}
                className="grid grid-cols-2 gap-3"
              >
                <StatCard icon={<Clock className="w-4 h-4 text-blue-500" />} label="المدة" value={stats.duration} />
                <StatCard icon={<Sparkles className="w-4 h-4 text-purple-500" />} label="الخطوات" value={`${stats.steps.length}`} />
                {stats.tokensUsed !== undefined && (
                  <StatCard icon={<Sparkles className="w-4 h-4 text-amber-500" />} label="التوكنز" value={stats.tokensUsed.toLocaleString()} />
                )}
                {stats.filesCreated !== undefined && stats.filesCreated > 0 && (
                  <StatCard icon={<Download className="w-4 h-4 text-green-500" />} label="الملفات" value={`${stats.filesCreated}`} />
                )}
              </motion.div>

              {stats.steps.length > 0 && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.4 }}
                  className="bg-muted/40 rounded-xl p-4 space-y-2 max-h-40 overflow-y-auto"
                >
                  <p className="text-xs font-semibold text-muted-foreground mb-2">الخطوات المنفّذة</p>
                  {stats.steps.map((step, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.45 + i * 0.04 }}
                      className="flex items-start gap-2 text-sm"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5 text-green-500 mt-0.5 shrink-0" />
                      <span className="text-foreground/80">{step}</span>
                    </motion.div>
                  ))}
                </motion.div>
              )}

              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 }}
                className="flex flex-col gap-2"
              >
                {summary && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full gap-2"
                    onClick={handleCopySummary}
                  >
                    <Copy className="w-4 h-4" />
                    {copied ? "تم النسخ ✓" : "نسخ الملخص"}
                  </Button>
                )}

                {downloadUrl && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full gap-2"
                    asChild
                  >
                    <a href={downloadUrl} download>
                      <Download className="w-4 h-4" />
                      تحميل التقرير
                    </a>
                  </Button>
                )}

                <div className="flex gap-2">
                  <Button
                    className="flex-1 gap-2 bg-green-600 hover:bg-green-700"
                    onClick={onNewTask}
                  >
                    <Plus className="w-4 h-4" />
                    مهمة جديدة
                  </Button>
                  {onContinue && (
                    <Button
                      variant="outline"
                      className="flex-1 gap-2"
                      onClick={onContinue}
                    >
                      متابعة
                      <ArrowRight className="w-4 h-4" />
                    </Button>
                  )}
                </div>
              </motion.div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="bg-muted/40 rounded-xl p-3 flex items-center gap-3 border border-border/50">
      <div className="shrink-0">{icon}</div>
      <div className="min-w-0">
        <p className="text-xs text-muted-foreground truncate">{label}</p>
        <p className="text-sm font-bold truncate">{value}</p>
      </div>
    </div>
  );
}
