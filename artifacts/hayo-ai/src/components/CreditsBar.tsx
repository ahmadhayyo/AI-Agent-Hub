/**
 * CreditsBar — عرض رصيد النقاط اليومي للمستخدم
 * يُستخدم في: Chat, WarRoom, Agent, OfficeSuite
 */
import { trpc } from "@/lib/trpc";
import { Zap, AlertCircle } from "lucide-react";

interface CreditsBarProps {
  className?: string;
  compact?: boolean;
  /** تكلفة العملية الحالية لعرض ما إذا كان الرصيد كافياً */
  operationCost?: number;
}

export default function CreditsBar({ className = "", compact = false, operationCost }: CreditsBarProps) {
  const { data, isLoading } = trpc.usage.credits.useQuery(undefined, {
    refetchInterval: 30_000,
    staleTime: 20_000,
  });

  if (isLoading || !data) return null;

  const { used, dailyLimit, remaining } = data;
  const pct = dailyLimit > 0 ? Math.min(100, (used / dailyLimit) * 100) : 0;
  const isLow = remaining < 5;
  const isOut = remaining <= 0;
  const canAfford = operationCost == null || remaining >= operationCost;

  const barColor = isOut
    ? "bg-red-500"
    : isLow
    ? "bg-amber-500"
    : "bg-primary";

  if (compact) {
    return (
      <div className={`flex items-center gap-1.5 text-xs ${className}`}>
        <Zap className={`w-3 h-3 ${isOut ? "text-red-500" : isLow ? "text-amber-500" : "text-primary"}`} />
        <span className={isOut ? "text-red-500 font-medium" : isLow ? "text-amber-500" : "text-muted-foreground"}>
          {remaining}/{dailyLimit} نقطة
        </span>
        {!canAfford && operationCost && (
          <AlertCircle className="w-3 h-3 text-red-500" />
        )}
      </div>
    );
  }

  return (
    <div className={`space-y-1.5 ${className}`}>
      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center gap-1.5 text-muted-foreground">
          <Zap className={`w-3.5 h-3.5 ${isOut ? "text-red-500" : isLow ? "text-amber-500" : "text-primary"}`} />
          <span className="font-medium">النقاط اليومية</span>
        </div>
        <span className={`font-mono font-semibold ${isOut ? "text-red-500" : isLow ? "text-amber-500" : "text-foreground"}`}>
          {remaining} / {dailyLimit}
        </span>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-secondary rounded-full h-1.5 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>

      {isOut && (
        <p className="text-[10px] text-red-500 flex items-center gap-1">
          <AlertCircle className="w-3 h-3" />
          نفدت نقاطك — يُجدد الرصيد يومياً عند منتصف الليل
        </p>
      )}
      {isLow && !isOut && (
        <p className="text-[10px] text-amber-500">رصيدك منخفض — {remaining} نقطة متبقية</p>
      )}
      {!canAfford && operationCost && !isOut && (
        <p className="text-[10px] text-red-500">
          هذه العملية تكلف {operationCost} نقاط — رصيدك الحالي {remaining}
        </p>
      )}
    </div>
  );
}
