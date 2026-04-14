/**
 * Model Settings Page — Customizable AI Instructions per Model
 * Admin-only: Edit system prompts for each AI model
 * Uses tRPC backend for real persistence
 */
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { RotateCcw, Save, ChevronDown, ChevronUp, Brain, Info, Loader2, CheckCircle2, AlertCircle } from "lucide-react";
import { motion } from "framer-motion";

interface ModelInstruction {
  modelId: string;
  name: string;
  icon: string;
  defaultInstruction: string;
  customInstruction?: string;
  activeInstruction: string;
  isCustomized: boolean;
}

function ModelCard({
  model,
  onSave,
  onReset,
  savingId,
}: {
  model: ModelInstruction;
  onSave: (modelId: string, instruction: string) => Promise<void>;
  onReset: (modelId: string) => Promise<void>;
  savingId: string | null;
}) {
  const [expanded, setExpanded] = useState(false);
  const [editValue, setEditValue] = useState(model.activeInstruction);
  const isSaving = savingId === model.modelId;
  const isModified = editValue !== model.activeInstruction;

  useEffect(() => {
    setEditValue(model.activeInstruction);
  }, [model.activeInstruction]);

  return (
    <div className={`bg-card/70 backdrop-blur-sm border rounded-xl overflow-hidden transition-all ${model.isCustomized ? "border-indigo-500/30" : "border-border/40"}`}>
      <div
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-accent/30 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <span className="text-2xl">{model.icon}</span>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-foreground">{model.name}</h3>
              {model.isCustomized && (
                <Badge variant="outline" className="text-xs border-indigo-500/50 text-indigo-400">
                  مخصص
                </Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
              {model.activeInstruction.substring(0, 80)}...
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {model.isCustomized && (
            <Button
              variant="ghost"
              size="sm"
              className="text-orange-400 hover:text-orange-300 text-xs"
              disabled={isSaving}
              onClick={e => { e.stopPropagation(); onReset(model.modelId); }}
            >
              <RotateCcw className="w-3 h-3 ml-1" />
              إعادة تعيين
            </Button>
          )}
          {expanded ? (
            <ChevronUp className="w-4 h-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="w-4 h-4 text-muted-foreground" />
          )}
        </div>
      </div>

      {expanded && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: "auto", opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          className="border-t border-border/40"
        >
          <div className="p-4 space-y-3">
            {model.isCustomized && (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/20">
                <CheckCircle2 className="w-4 h-4 text-indigo-400 mt-0.5 flex-shrink-0" />
                <p className="text-xs text-indigo-300">
                  هذا النموذج يستخدم تعليمات مخصصة محفوظة في الخادم. التعليمات تُضاف تلقائياً في بداية كل محادثة.
                </p>
              </div>
            )}

            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                تعليمات النموذج (System Prompt)
              </label>
              <Textarea
                value={editValue}
                onChange={e => setEditValue(e.target.value)}
                className="min-h-[160px] text-sm font-mono resize-none bg-background/50 border-border/60 focus:border-indigo-500/50"
                placeholder="أدخل التعليمات المخصصة لهذا النموذج..."
                dir="rtl"
              />
              <div className="flex items-center justify-between mt-1">
                <p className="text-xs text-muted-foreground">
                  {editValue.length} حرف
                </p>
                {isModified && (
                  <p className="text-xs text-amber-400">تغييرات غير محفوظة</p>
                )}
              </div>
            </div>

            {model.isCustomized && (
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                  التعليمات الافتراضية (للمرجع)
                </label>
                <div className="p-3 rounded-lg bg-background/50 border border-border/40 text-xs text-muted-foreground font-mono leading-relaxed max-h-24 overflow-y-auto" dir="rtl">
                  {model.defaultInstruction}
                </div>
              </div>
            )}

            <div className="flex gap-2 justify-end">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setEditValue(model.defaultInstruction)}
                className="text-xs"
                disabled={isSaving}
              >
                استعادة الافتراضي
              </Button>
              <Button
                size="sm"
                onClick={() => onSave(model.modelId, editValue)}
                disabled={isSaving || !isModified}
                className="bg-indigo-600 hover:bg-indigo-700 text-white text-xs gap-1 min-w-[120px]"
              >
                {isSaving ? (
                  <><Loader2 className="w-3 h-3 animate-spin" />جاري الحفظ...</>
                ) : (
                  <><Save className="w-3 h-3" />حفظ التعليمات</>
                )}
              </Button>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}

export default function ModelSettings() {
  const [savingId, setSavingId] = useState<string | null>(null);

  const { data: models, isLoading, error, refetch } = trpc.modelInstructions.getAll.useQuery(undefined, {
    retry: 2,
    staleTime: 30000,
  });

  const updateMutation = trpc.modelInstructions.update.useMutation({
    onSuccess: (_data, variables) => {
      toast.success(`تم حفظ تعليمات ${models?.find(m => m.modelId === variables.modelId)?.name || variables.modelId} في الخادم`);
      refetch();
    },
    onError: (err) => {
      toast.error(`فشل الحفظ: ${err.message}`);
    },
    onSettled: () => {
      setSavingId(null);
    },
  });

  const resetMutation = trpc.modelInstructions.reset.useMutation({
    onSuccess: (_data, variables) => {
      toast.success(`تم إعادة تعيين ${models?.find(m => m.modelId === variables.modelId)?.name || variables.modelId} للتعليمات الافتراضية`);
      refetch();
    },
    onError: (err) => {
      toast.error(`فشل إعادة التعيين: ${err.message}`);
    },
    onSettled: () => {
      setSavingId(null);
    },
  });

  const handleSave = async (modelId: string, instruction: string) => {
    setSavingId(modelId);
    updateMutation.mutate({ modelId, instruction });
  };

  const handleReset = async (modelId: string) => {
    setSavingId(modelId);
    resetMutation.mutate({ modelId });
  };

  return (
    <div className="min-h-screen bg-background text-foreground p-4 md:p-8">
      <div className="max-w-3xl mx-auto">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/20 flex items-center justify-center">
              <Brain className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <h1 className="font-heading text-2xl font-bold text-foreground">إعدادات النماذج</h1>
              <p className="text-sm text-muted-foreground">تخصيص تعليمات النظام لكل نموذج AI</p>
            </div>
          </div>

          <div className="mt-4 p-4 rounded-xl bg-indigo-500/10 border border-indigo-500/20">
            <p className="text-sm text-indigo-300 leading-relaxed">
              <strong>كيف يعمل:</strong> كل نموذج AI لديه تعليمات نظام افتراضية. يمكنك تخصيص هذه التعليمات لكل نموذج على حدة.
              التعليمات المخصصة تُضاف تلقائياً في بداية كل محادثة مع هذا النموذج.
              <br />
              <strong className="text-indigo-200">التخزين:</strong> التعليمات محفوظة في الخادم وتبقى فعّالة حتى إعادة تشغيله.
            </p>
          </div>
        </div>

        {isLoading && (
          <div className="flex items-center justify-center py-12 gap-3">
            <Loader2 className="w-6 h-6 animate-spin text-indigo-400" />
            <span className="text-muted-foreground">جاري تحميل إعدادات النماذج...</span>
          </div>
        )}

        {error && (
          <div className="flex items-center gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400">
            <AlertCircle className="w-5 h-5 shrink-0" />
            <div>
              <p className="font-medium">فشل تحميل الإعدادات</p>
              <p className="text-xs mt-1 opacity-80">{error.message}</p>
            </div>
            <Button variant="outline" size="sm" onClick={() => refetch()} className="mr-auto text-xs">
              إعادة المحاولة
            </Button>
          </div>
        )}

        {models && (
          <div className="space-y-3">
            {models.map((model: any, i: number) => (
              <motion.div
                key={model.modelId}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.07 }}
              >
                <ModelCard model={model} onSave={handleSave} onReset={handleReset} savingId={savingId} />
              </motion.div>
            ))}
          </div>
        )}

        <div className="mt-8 p-4 rounded-xl bg-background/50 border border-border/40">
          <div className="flex items-start gap-2">
            <Info className="w-4 h-4 text-muted-foreground mt-0.5 shrink-0" />
            <p className="text-xs text-muted-foreground">
              التعليمات المخصصة تُستخدم كـ System Prompt عند استدعاء كل نموذج في المحادثة أو التحليل.
              يمكنك مثلاً تحديد أسلوب الإجابة، اللغة المفضلة، التخصص المطلوب، أو أي تعليمات خاصة.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
