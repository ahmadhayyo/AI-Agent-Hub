import { z } from "zod";
import { TRPCError } from "@trpc/server";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { router, publicProcedure, protectedProcedure, adminProcedure } from "./trpc";
import { reverseEngineerRouter } from "./reverse-engineer-router";
import { aiAgentRouter } from "./ai-agent-router";
import { getTwelveDataKey, markKeyExhausted, isRateLimitError, rotateToNextKey, checkAndMarkIfDailyExhausted, getKeyStats } from "../lib/twelvedata-keys";

async function fetchTwelveData(url: string): Promise<any> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const apiKey = getTwelveDataKey();
    if (!apiKey) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "لا توجد مفاتيح TwelveData متاحة" });
    const fullUrl = url.replace("__API_KEY__", apiKey);
    try {
      const res = await fetch(fullUrl, { signal: AbortSignal.timeout(12000) });
      if (res.status === 429) {
        rotateToNextKey();
        await new Promise(r => setTimeout(r, 8000));
        continue;
      }
      if (!res.ok) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `TwelveData HTTP ${res.status}` });
      const data = await res.json() as any;
      if (data.status === "error" && isRateLimitError(data)) {
        const isDailyDone = await checkAndMarkIfDailyExhausted(apiKey);
        if (!isDailyDone) {
          rotateToNextKey();
          await new Promise(r => setTimeout(r, 8000));
        }
        continue;
      }
      return data;
    } catch (err: any) {
      if (err instanceof TRPCError) throw err;
      if (attempt < 7) { await new Promise(r => setTimeout(r, 3000)); continue; }
      throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message || "فشل الاتصال بـ TwelveData" });
    }
  }
  throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "نفد رصيد جميع مفاتيح TwelveData اليوم — يتجدد غداً" });
}

import {
  createUser, loginUser, getUserById, getAllUsers, getAdminStats,
  createConversation, getUserConversations, getConversation,
  updateConversationTitle, deleteConversation,
  addMessage, getConversationMessages,
  saveUploadedFile, getUserFiles, getFileById,
  getActivePlans, getPlanById, seedDefaultPlans, seedOwnerAccount,
  getUserActiveSubscription, createSubscription,
  getOrCreateDailyUsage, incrementUsage,
  checkCredits, deductCredits, CREDIT_COSTS,
  getUserIntegrations, connectIntegration, disconnectIntegration, deleteFile,
} from "./db";
import { createSessionToken, setCookie, clearCookie, COOKIE_NAME } from "./auth";
import { invokeLLM, type Message } from "./llm";
import { callProvider, getAvailableProviders, isProviderAvailable, PROVIDER_CONFIGS, type AIProvider } from "./providers";

// Delay seeding to allow healthcheck to pass first
setTimeout(() => {
  seedDefaultPlans().catch(err => console.error("[Seed] Failed to seed plans:", err));
  seedOwnerAccount().catch(err => console.error("[Seed] Failed to seed owner:", err));
}, 5000);

// ── Desktop download token store (in-memory, 24h TTL) ────────────
export const desktopDownloadMap = new Map<string, { zipPath: string; filename: string; expiresAt: number }>();

// ─── Technical Indicator Helpers ─────────────────────────────────────
function calcSMA(arr: number[], period: number): number {
  if (arr.length < period) return arr[arr.length - 1] ?? 0;
  const slice = arr.slice(-period);
  return slice.reduce((a, b) => a + b, 0) / period;
}
function calcEMA(arr: number[], period: number): number {
  if (arr.length === 0) return 0;
  const k = 2 / (period + 1);
  let ema = arr[0];
  for (let i = 1; i < arr.length; i++) ema = arr[i] * k + ema * (1 - k);
  return ema;
}
function calcRSI(closes: number[], period = 14): number {
  if (closes.length < period + 1) return 50;
  let gains = 0, losses = 0;
  for (let i = closes.length - period; i < closes.length; i++) {
    const d = closes[i] - closes[i - 1];
    if (d > 0) gains += d; else losses -= d;
  }
  const ag = gains / period, al = losses / period;
  if (al === 0) return 100;
  return 100 - 100 / (1 + ag / al);
}
function calcMACD(closes: number[]) {
  if (closes.length < 26) return { macd: 0, signal: 0, histogram: 0 };
  const ema12 = calcEMA(closes, 12);
  const ema26 = calcEMA(closes, 26);
  const macdLine = ema12 - ema26;

  // Build MACD line history for proper EMA(9) signal
  const macdHistory: number[] = [];
  for (let i = 26; i <= closes.length; i++) {
    const slice = closes.slice(0, i);
    macdHistory.push(calcEMA(slice, 12) - calcEMA(slice, 26));
  }
  const signalLine = macdHistory.length >= 9 ? calcEMA(macdHistory, 9) : macdLine;
  return { macd: macdLine, signal: signalLine, histogram: macdLine - signalLine };
}
function calcBB(closes: number[], period = 20, mult = 2) {
  const middle = calcSMA(closes, period);
  const slice  = closes.slice(-period);
  const variance = slice.reduce((s, v) => s + Math.pow(v - middle, 2), 0) / period;
  const sd = Math.sqrt(variance);
  return { upper: middle + mult * sd, middle, lower: middle - mult * sd };
}
function calcATR(highs: number[], lows: number[], closes: number[], period = 14): number {
  const trs: number[] = [];
  for (let i = 1; i < highs.length; i++) {
    trs.push(Math.max(highs[i] - lows[i], Math.abs(highs[i] - closes[i - 1]), Math.abs(lows[i] - closes[i - 1])));
  }
  if (trs.length === 0) return 0;
  return calcSMA(trs, period);
}

// Stochastic Oscillator (%K, %D)
function calcStochastic(closes: number[], highs: number[], lows: number[], kPeriod = 14, dPeriod = 3): { k: number; d: number } {
  if (closes.length < kPeriod) return { k: 50, d: 50 };
  const recentHighs = highs.slice(-kPeriod);
  const recentLows = lows.slice(-kPeriod);
  const highestHigh = Math.max(...recentHighs);
  const lowestLow = Math.min(...recentLows);
  const range = highestHigh - lowestLow;
  const k = range === 0 ? 50 : ((closes[closes.length - 1] - lowestLow) / range) * 100;

  // %D = SMA of recent %K values
  const kValues: number[] = [];
  for (let i = Math.max(kPeriod, closes.length - dPeriod * 2); i <= closes.length; i++) {
    const sliceH = highs.slice(Math.max(0, i - kPeriod), i);
    const sliceL = lows.slice(Math.max(0, i - kPeriod), i);
    const sliceC = closes.slice(0, i);
    if (sliceH.length < kPeriod) continue;
    const hh = Math.max(...sliceH);
    const ll = Math.min(...sliceL);
    const rng = hh - ll;
    kValues.push(rng === 0 ? 50 : ((sliceC[sliceC.length - 1] - ll) / rng) * 100);
  }
  const d = kValues.length >= dPeriod ? calcSMA(kValues, dPeriod) : k;
  return { k, d };
}

// Williams %R
function calcWilliamsR(closes: number[], highs: number[], lows: number[], period = 14): number {
  if (closes.length < period) return -50;
  const recentHighs = highs.slice(-period);
  const recentLows = lows.slice(-period);
  const hh = Math.max(...recentHighs);
  const ll = Math.min(...recentLows);
  const range = hh - ll;
  return range === 0 ? -50 : ((hh - closes[closes.length - 1]) / range) * -100;
}

// Pivot Points (Standard)
function calcPivotPoints(highs: number[], lows: number[], closes: number[]): {
  pivot: number; r1: number; r2: number; r3: number; s1: number; s2: number; s3: number;
} {
  const h = highs[highs.length - 1] || 0;
  const l = lows[lows.length - 1] || 0;
  const c = closes[closes.length - 1] || 0;
  const pivot = (h + l + c) / 3;
  return {
    pivot,
    r1: 2 * pivot - l, r2: pivot + (h - l), r3: h + 2 * (pivot - l),
    s1: 2 * pivot - h, s2: pivot - (h - l), s3: l - 2 * (h - pivot),
  };
}

// ADX (Average Directional Index) — trend strength
function calcADX(highs: number[], lows: number[], closes: number[], period = 14): { adx: number; pdi: number; mdi: number } {
  if (highs.length < period + 1) return { adx: 25, pdi: 25, mdi: 25 };
  const pdm: number[] = [];
  const mdm: number[] = [];
  const tr: number[] = [];

  for (let i = 1; i < highs.length; i++) {
    const upMove = highs[i] - highs[i - 1];
    const downMove = lows[i - 1] - lows[i];
    pdm.push(upMove > downMove && upMove > 0 ? upMove : 0);
    mdm.push(downMove > upMove && downMove > 0 ? downMove : 0);
    tr.push(Math.max(highs[i] - lows[i], Math.abs(highs[i] - closes[i - 1]), Math.abs(lows[i] - closes[i - 1])));
  }

  const smoothTR = calcEMA(tr, period);
  const smoothPDM = calcEMA(pdm, period);
  const smoothMDM = calcEMA(mdm, period);
  const pdi = smoothTR > 0 ? (smoothPDM / smoothTR) * 100 : 0;
  const mdi = smoothTR > 0 ? (smoothMDM / smoothTR) * 100 : 0;
  const dx = (pdi + mdi) > 0 ? Math.abs(pdi - mdi) / (pdi + mdi) * 100 : 0;

  // Simplified ADX — ideally EMA of DX history
  const adx = dx;
  return { adx, pdi, mdi };
}

// ─── Strategy & Filter Types ──────────────────────────────────────────
interface StrategySignal {
  id: string;
  name: string;
  signal: "BUY" | "SELL" | "NEUTRAL";
  strength: number;
  desc: string;
  emoji: string;
}
interface FilterResult {
  id: string;
  name: string;
  passed: boolean;
  allowsBuy: boolean;
  allowsSell: boolean;
  desc: string;
  emoji: string;
}

// ─── Strategy Calculators ─────────────────────────────────────────────
function calcStrategies(
  closes: number[], highs: number[], lows: number[],
  sma20: number, sma50: number, sma200: number | null,
  rsi: number, macd: { macd: number; signal: number; histogram: number },
  bb: { upper: number; middle: number; lower: number },
  atr: number,
  stoch?: { k: number; d: number },
  williamsR?: number,
  adx?: { adx: number; pdi: number; mdi: number },
  pivots?: { pivot: number; r1: number; r2: number; r3: number; s1: number; s2: number; s3: number },
): StrategySignal[] {
  const price = closes[closes.length - 1];
  const prevPrice = closes[closes.length - 2] || price;
  const signals: StrategySignal[] = [];

  // 1 — Trend Following (SMA Alignment)
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if (sma200) {
      if (price > sma20 && sma20 > sma50 && sma50 > sma200) { sig = "BUY";  str = 88; }
      else if (price < sma20 && sma20 < sma50 && sma50 < sma200) { sig = "SELL"; str = 88; }
      else if (price > sma20 && sma20 > sma50) { sig = "BUY";  str = 65; }
      else if (price < sma20 && sma20 < sma50) { sig = "SELL"; str = 65; }
    } else {
      if (price > sma20 && sma20 > sma50) { sig = "BUY";  str = 70; }
      else if (price < sma20 && sma20 < sma50) { sig = "SELL"; str = 70; }
    }
    signals.push({ id: "trend_following", name: "تتبع الاتجاه", emoji: "🎯",
      signal: sig, strength: str,
      desc: sig === "BUY" ? "المتوسطات المتحركة في تصاعد متوافق (SMA20>50>200)" :
            sig === "SELL" ? "المتوسطات المتحركة في تراجع متوافق (SMA20<50<200)" :
            "لا توافق واضح بين المتوسطات المتحركة" });
  }

  // 2 — Breakout / Bollinger Bands
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    const bbWidth = (bb.upper - bb.lower) / bb.middle * 100;
    if (bbWidth < 0.8) {
      sig = "NEUTRAL"; str = 0;
    } else if (prevPrice <= bb.lower && price > bb.lower) {
      sig = "BUY"; str = 82;
    } else if (prevPrice >= bb.upper && price < bb.upper) {
      sig = "SELL"; str = 82;
    } else if (price < bb.lower) {
      sig = "BUY"; str = 68;
    } else if (price > bb.upper) {
      sig = "SELL"; str = 68;
    }
    signals.push({ id: "breakout", name: "الاختراق (Bollinger)", emoji: "💥",
      signal: sig, strength: str,
      desc: bbWidth < 0.8 ? "النطاقات ضيقة جداً — انتظار اختراق وشيك" :
            sig === "BUY" ? "ارتداد من النطاق السفلي — إشارة صعود" :
            sig === "SELL" ? "ارتداد من النطاق العلوي — إشارة هبوط" :
            `السعر داخل النطاق الطبيعي (عرض ${bbWidth.toFixed(2)}%)` });
  }

  // 3 — RSI Momentum
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if      (rsi < 20) { sig = "BUY";  str = 92; }
    else if (rsi < 30) { sig = "BUY";  str = 78; }
    else if (rsi < 38) { sig = "BUY";  str = 58; }
    else if (rsi > 80) { sig = "SELL"; str = 92; }
    else if (rsi > 70) { sig = "SELL"; str = 78; }
    else if (rsi > 62) { sig = "SELL"; str = 58; }
    signals.push({ id: "rsi_momentum", name: "زخم RSI", emoji: "⚡",
      signal: sig, strength: str,
      desc: `RSI = ${rsi.toFixed(1)} — ${rsi < 30 ? "ذروة بيع قوية 🔴" : rsi < 38 ? "اقتراب ذروة بيع" : rsi > 70 ? "ذروة شراء قوية 🟢" : rsi > 62 ? "اقتراب ذروة شراء" : "منطقة محايدة (40-60)"}` });
  }

  // 4 — MACD Crossover
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if (macd.histogram > 0 && macd.macd > macd.signal) {
      sig = "BUY";  str = Math.min(88, 50 + Math.round(Math.abs(macd.histogram) / (Math.abs(macd.macd) || 1) * 80));
    } else if (macd.histogram < 0 && macd.macd < macd.signal) {
      sig = "SELL"; str = Math.min(88, 50 + Math.round(Math.abs(macd.histogram) / (Math.abs(macd.macd) || 1) * 80));
    }
    signals.push({ id: "macd_crossover", name: "تقاطع MACD", emoji: "📊",
      signal: sig, strength: str,
      desc: `MACD ${macd.macd > macd.signal ? "فوق" : "تحت"} خط الإشارة | Histogram: ${macd.histogram.toFixed(5)}` });
  }

  // 5 — Scalping (Mean Reversion from SMA20)
  {
    const dist = (price - sma20) / sma20 * 100;
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if      (dist < -0.20) { sig = "BUY";  str = 75; }
    else if (dist < -0.10) { sig = "BUY";  str = 58; }
    else if (dist >  0.20) { sig = "SELL"; str = 75; }
    else if (dist >  0.10) { sig = "SELL"; str = 58; }
    signals.push({ id: "scalping", name: "سكالبينج (ارتداد)", emoji: "⚡",
      signal: sig, strength: str,
      desc: `البعد عن SMA20: ${dist >= 0 ? "+" : ""}${dist.toFixed(3)}% — ${sig === "BUY" ? "السعر بعيد أسفل المتوسط" : sig === "SELL" ? "السعر بعيد فوق المتوسط" : "السعر قريب من المتوسط"}` });
  }

  // 6 — Swing Trading (Pullback to SMA50)
  {
    const distSMA50 = Math.abs(price - sma50) / sma50 * 100;
    const nearSMA50 = distSMA50 < 0.18;
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if (nearSMA50 && sma20 > sma50)          { sig = "BUY";  str = 74; }
    else if (nearSMA50 && sma20 < sma50)     { sig = "SELL"; str = 74; }
    else if (price > sma50 && rsi < 48)      { sig = "BUY";  str = 62; }
    else if (price < sma50 && rsi > 52)      { sig = "SELL"; str = 62; }
    signals.push({ id: "swing", name: "سوينغ ترادينج", emoji: "🌊",
      signal: sig, strength: str,
      desc: nearSMA50 ? `السعر قريب من SMA50 — نقطة انعكاس محتملة (${distSMA50.toFixed(3)}%)` :
            `انتظار تصحيح نحو SMA50 (بُعد: ${distSMA50.toFixed(3)}%)` });
  }

  // 7 — Support & Resistance (Swing Levels + Touch Count)
  {
    const pDecimals = price > 100 ? 2 : price > 10 ? 3 : 5;
    const fmt5 = (n: number) => n.toFixed(pDecimals);

    // Detect swing highs and lows (require 3 candles on each side)
    const swing = 3;
    const swingHighs: number[] = [];
    const swingLows:  number[] = [];
    for (let i = swing; i < highs.length - swing; i++) {
      let isH = true, isL = true;
      for (let j = i - swing; j <= i + swing; j++) {
        if (j === i) continue;
        if (highs[j] >= highs[i]) isH = false;
        if (lows[j]  <= lows[i])  isL = false;
      }
      if (isH) swingHighs.push(highs[i]);
      if (isL) swingLows.push(lows[i]);
    }

    // Cluster nearby swing levels (within 1 ATR = same zone)
    const clusterTol = atr;
    function clusterLevels(levels: number[]): { price: number; touches: number }[] {
      const groups: { price: number; count: number }[] = [];
      for (const lvl of levels) {
        const g = groups.find(g => Math.abs(g.price - lvl) <= clusterTol);
        if (g) {
          g.price = (g.price * g.count + lvl) / (g.count + 1); // weighted average
          g.count++;
        } else {
          groups.push({ price: lvl, count: 1 });
        }
      }
      return groups.map(g => ({ price: g.price, touches: g.count }));
    }

    const allRes = clusterLevels(swingHighs)
      .filter(l => l.price > price)
      .sort((a, b) => a.price - b.price); // nearest first

    const allSup = clusterLevels(swingLows)
      .filter(l => l.price < price)
      .sort((a, b) => b.price - a.price); // nearest first

    // Confirmed levels need ≥3 touches (2 bounces confirmed)
    // Potential levels: 2 touches (1 bounce confirmed — awaiting 3rd touch)
    // Weak levels: 1 touch only
    const validRes     = allRes.filter(l => l.touches >= 3); // confirmed resistance
    const validSup     = allSup.filter(l => l.touches >= 3); // confirmed support
    const potentialRes = allRes.filter(l => l.touches === 2); // 1 bounce, waiting 3rd
    const potentialSup = allSup.filter(l => l.touches === 2);
    const weakRes      = allRes.filter(l => l.touches === 1);
    const weakSup      = allSup.filter(l => l.touches === 1);

    const nearestRes = validRes[0] ?? null;
    const nearestSup = validSup[0] ?? null;
    const nearestPotRes = potentialRes[0] ?? null;
    const nearestPotSup = potentialSup[0] ?? null;
    const nearestWeakRes = weakRes[0] ?? null;
    const nearestWeakSup = weakSup[0] ?? null;

    // "Near" = within 0.5 ATR of a valid level
    const proximity = atr * 0.5;
    const nearRes    = nearestRes    && Math.abs(price - nearestRes.price)    <= proximity;
    const nearSup    = nearestSup    && Math.abs(price - nearestSup.price)    <= proximity;
    const nearPotRes = nearestPotRes && Math.abs(price - nearestPotRes.price) <= proximity;
    const nearPotSup = nearestPotSup && Math.abs(price - nearestPotSup.price) <= proximity;

    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    let desc = "";

    if (nearSup && nearestSup) {
      // ✅ At confirmed support (3+ touches = 2 bounces confirmed) → strong BUY
      sig = "BUY";
      str = Math.min(95, 80 + nearestSup.touches * 4);
      desc = `دعم مؤكد عند ${fmt5(nearestSup.price)} (${nearestSup.touches} لمسات — ${nearestSup.touches - 1} ارتداد مؤكد ✅) — ارتداد صعودي قوي متوقع`;
    } else if (nearRes && nearestRes) {
      // ✅ At confirmed resistance (3+ touches = 2 bounces confirmed) → strong SELL
      sig = "SELL";
      str = Math.min(95, 80 + nearestRes.touches * 4);
      desc = `مقاومة مؤكدة عند ${fmt5(nearestRes.price)} (${nearestRes.touches} لمسات — ${nearestRes.touches - 1} ارتداد مؤكد ✅) — ارتداد هبوطي قوي متوقع`;
    } else if (nearPotSup && nearestPotSup) {
      // ⚡ Near potential support (2 touches = 1 bounce — await 3rd for confirmation)
      sig = "NEUTRAL";
      str = 0;
      desc = `⚡ مستوى دعم محتمل عند ${fmt5(nearestPotSup.price)} (لمستان، ارتداد واحد) — بانتظار اللمسة الثالثة للتأكيد`;
    } else if (nearPotRes && nearestPotRes) {
      // ⚡ Near potential resistance (2 touches = 1 bounce — await 3rd for confirmation)
      sig = "NEUTRAL";
      str = 0;
      desc = `⚡ مستوى مقاومة محتمل عند ${fmt5(nearestPotRes.price)} (لمستان، ارتداد واحد) — بانتظار اللمسة الثالثة للتأكيد`;
    } else {
      // 🟡 Between levels — show context
      const supLabel = nearestSup    ? `${fmt5(nearestSup.price)} (${nearestSup.touches}x ✅)`
                     : nearestPotSup ? `${fmt5(nearestPotSup.price)} (2x ⚡ محتمل)`
                     : nearestWeakSup ? `${fmt5(nearestWeakSup.price)} (1x ضعيف)` : "—";
      const resLabel = nearestRes    ? `${fmt5(nearestRes.price)} (${nearestRes.touches}x ✅)`
                     : nearestPotRes ? `${fmt5(nearestPotRes.price)} (2x ⚡ محتمل)`
                     : nearestWeakRes ? `${fmt5(nearestWeakRes.price)} (1x ضعيف)` : "—";
      desc = `السعر بين مستويات | أقرب دعم: ${supLabel} | أقرب مقاومة: ${resLabel}`;
    }

    signals.push({
      id: "support_resistance", name: "دعم ومقاومة", emoji: "🏛️",
      signal: sig, strength: str, desc,
    });
  }

  // 8 — Stochastic Crossover
  if (stoch) {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if (stoch.k < 20 && stoch.k > stoch.d) { sig = "BUY"; str = 82; }
    else if (stoch.k > 80 && stoch.k < stoch.d) { sig = "SELL"; str = 82; }
    else if (stoch.k < 30 && stoch.k > stoch.d) { sig = "BUY"; str = 65; }
    else if (stoch.k > 70 && stoch.k < stoch.d) { sig = "SELL"; str = 65; }
    signals.push({ id: "stochastic", name: "تقاطع Stochastic", emoji: "🔄",
      signal: sig, strength: str,
      desc: `%K=${stoch.k.toFixed(1)} %D=${stoch.d.toFixed(1)} — ${
        stoch.k < 20 ? "ذروة بيع شديدة" : stoch.k > 80 ? "ذروة شراء شديدة" :
        stoch.k > stoch.d ? "تقاطع صاعد" : stoch.k < stoch.d ? "تقاطع هابط" : "محايد"
      }` });
  }

  // 9 — ADX Trend Strength Confirmation
  if (adx) {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if (adx.adx > 25 && adx.pdi > adx.mdi) { sig = "BUY"; str = Math.min(90, 55 + Math.round(adx.adx)); }
    else if (adx.adx > 25 && adx.mdi > adx.pdi) { sig = "SELL"; str = Math.min(90, 55 + Math.round(adx.adx)); }
    signals.push({ id: "adx_trend", name: "قوة الاتجاه ADX", emoji: "💪",
      signal: sig, strength: str,
      desc: `ADX=${adx.adx.toFixed(1)} | +DI=${adx.pdi.toFixed(1)} -DI=${adx.mdi.toFixed(1)} — ${
        adx.adx > 40 ? "اتجاه قوي جداً 🔥" : adx.adx > 25 ? "اتجاه واضح" : "سوق جانبي — لا إشارة"
      }` });
  }

  // 10 — Pivot Point Bounce
  if (pivots) {
    const price = closes[closes.length - 1];
    const tolerance = atr * 0.3;
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    let desc = "";
    if (Math.abs(price - pivots.s1) < tolerance) { sig = "BUY"; str = 75; desc = `ارتداد من S1 (${pivots.s1.toFixed(2)})`; }
    else if (Math.abs(price - pivots.s2) < tolerance) { sig = "BUY"; str = 85; desc = `ارتداد من S2 (${pivots.s2.toFixed(2)}) — دعم قوي`; }
    else if (Math.abs(price - pivots.r1) < tolerance) { sig = "SELL"; str = 75; desc = `ارتداد من R1 (${pivots.r1.toFixed(2)})`; }
    else if (Math.abs(price - pivots.r2) < tolerance) { sig = "SELL"; str = 85; desc = `ارتداد من R2 (${pivots.r2.toFixed(2)}) — مقاومة قوية`; }
    else if (price > pivots.pivot) { desc = `فوق Pivot (${pivots.pivot.toFixed(2)}) — نطاق صعودي`; }
    else { desc = `تحت Pivot (${pivots.pivot.toFixed(2)}) — نطاق هبوطي`; }
    signals.push({ id: "pivot_bounce", name: "ارتداد Pivot", emoji: "📍",
      signal: sig, strength: str, desc });
  }

  return signals;
}

// ─── Filter Calculators ───────────────────────────────────────────────
function calcFilters(
  price: number, sma20: number, sma50: number, sma200: number | null,
  rsi: number, atr: number, closes: number[],
): FilterResult[] {
  const filters: FilterResult[] = [];

  // 1 — Major Trend Filter
  {
    const ref = sma200 || sma50;
    const bull = price > ref;
    filters.push({ id: "trend_filter", name: "الاتجاه الرئيسي", emoji: "🧭",
      passed: true, allowsBuy: bull, allowsSell: !bull,
      desc: bull
        ? `📈 اتجاه صاعد (السعر فوق ${sma200 ? "SMA200" : "SMA50"}) — يفضّل البيع يُصفَّى`
        : `📉 اتجاه هابط (السعر تحت ${sma200 ? "SMA200" : "SMA50"}) — يفضّل الشراء يُصفَّى` });
  }

  // 2 — Volatility Filter (ATR ratio)
  {
    const avgMove = calcSMA(closes.slice(-20).map((c, i, a) => i > 0 ? Math.abs(c - a[i - 1]) : 0).slice(1), 14);
    const ratio = avgMove > 0 ? atr / avgMove : 1;
    const high = ratio > 2.8;
    const low  = ratio < 0.35;
    filters.push({ id: "volatility_filter", name: "فلتر التقلب", emoji: "📉",
      passed: !high, allowsBuy: !high, allowsSell: !high,
      desc: high ? `⚠️ تقلب مفرط (${ratio.toFixed(2)}x) — خطر عالٍ` :
            low  ? `😴 تقلب منخفض جداً (${ratio.toFixed(2)}x) — سوق راكد` :
            `✅ تقلب طبيعي (${ratio.toFixed(2)}x المعدل)` });
  }

  // 3 — RSI Confirmation Filter
  {
    const buyOk  = rsi < 65;
    const sellOk = rsi > 35;
    filters.push({ id: "rsi_filter", name: "تأكيد RSI", emoji: "📡",
      passed: true, allowsBuy: buyOk, allowsSell: sellOk,
      desc: `RSI = ${rsi.toFixed(1)} — ${buyOk && sellOk ? "يسمح بكلا الاتجاهين" : buyOk ? "✅ يدعم الشراء فقط" : "✅ يدعم البيع فقط"}` });
  }

  // 4 — Session Filter (UTC)
  {
    const h = new Date().getUTCHours();
    const overlap  = h >= 13 && h < 16;
    const london   = h >= 8  && h < 16;
    const newYork  = h >= 13 && h < 21;
    const asian    = h >= 0  && h < 8;
    const active   = london || newYork;
    const session  = overlap ? "تداخل London/NY 🔥" : london ? "جلسة London 🇬🇧" : newYork ? "جلسة New York 🇺🇸" : asian ? "جلسة آسيا 🌏" : "بين الجلسات";
    filters.push({ id: "session_filter", name: "فلتر الجلسة", emoji: "🕐",
      passed: active, allowsBuy: active, allowsSell: active,
      desc: `${session} — UTC ${String(h).padStart(2, "0")}:${String(new Date().getUTCMinutes()).padStart(2, "0")} ${active ? "✅ جلسة نشطة" : "⚠️ خارج الجلسات الرئيسية"}` });
  }

  return filters;
}

export const appRouter = router({
  // ==================== Auth ====================
  auth: router({
    me: publicProcedure.query(({ ctx }) => ctx.user ?? null),

    register: publicProcedure
      .input(z.object({ name: z.string().min(2), email: z.string().email(), password: z.string().min(6) }))
      .mutation(async ({ input, ctx }) => {
        try {
          const user = await createUser(input);
          const token = await createSessionToken(user.id, user.role);
          setCookie(ctx.res, ctx.req, token);
          return { user };
        } catch (err: any) {
          throw new TRPCError({ code: "BAD_REQUEST", message: err.message });
        }
      }),

    login: publicProcedure
      .input(z.object({ email: z.string().email(), password: z.string() }))
      .mutation(async ({ input, ctx }) => {
        try {
          const user = await loginUser(input.email, input.password);
          const token = await createSessionToken(user.id, user.role);
          setCookie(ctx.res, ctx.req, token);
          return { user };
        } catch (err: any) {
          throw new TRPCError({ code: "UNAUTHORIZED", message: err.message });
        }
      }),

    logout: publicProcedure.mutation(({ ctx }) => {
      clearCookie(ctx.res, ctx.req);
      return { success: true };
    }),
  }),

  // ==================== Conversations ====================
  conversations: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      return getUserConversations(ctx.user.id);
    }),

    create: protectedProcedure
      .input(z.object({
        title: z.string().default("محادثة جديدة"),
        systemPrompt: z.string().optional(),
        agentMode: z.string().optional(),
        model: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await createConversation({ ...input, userId: ctx.user.id });
        return { id };
      }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input, ctx }) => {
        const conv = await getConversation(input.id, ctx.user.id);
        if (!conv) throw new TRPCError({ code: "NOT_FOUND", message: "المحادثة غير موجودة" });
        const msgs = await getConversationMessages(input.id);
        return { conversation: conv, messages: msgs };
      }),

    updateTitle: protectedProcedure
      .input(z.object({ id: z.number(), title: z.string() }))
      .mutation(async ({ input }) => {
        await updateConversationTitle(input.id, input.title);
        return { success: true };
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        await deleteConversation(input.id);
        return { success: true };
      }),
  }),

  // ==================== Chat ====================
  chat: router({
    send: protectedProcedure
      .input(z.object({
        conversationId: z.number(),
        content: z.string(),
        attachments: z.array(z.object({
          name: z.string(), url: z.string(), type: z.string(), size: z.number(),
        })).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const conv = await getConversation(input.conversationId, ctx.user.id);
        if (!conv) throw new TRPCError({ code: "NOT_FOUND", message: "المحادثة غير موجودة" });

        const userMsgId = await addMessage({
          conversationId: input.conversationId,
          role: "user",
          content: input.content,
          attachments: input.attachments,
        });

        const history = await getConversationMessages(input.conversationId);
        const llmMessages: Message[] = history
          .filter(m => m.role !== "system")
          .map(m => ({ role: m.role as "user" | "assistant", content: m.content }));

        const aiResponse = await invokeLLM(llmMessages, conv.systemPrompt ?? undefined);

        const aiMsgId = await addMessage({
          conversationId: input.conversationId,
          role: "assistant",
          content: aiResponse,
        });

        await incrementUsage(ctx.user.id);

        return {
          userMessageId: userMsgId,
          assistantMessageId: aiMsgId,
          content: aiResponse,
        };
      }),

    getMessages: protectedProcedure
      .input(z.object({ conversationId: z.number() }))
      .query(async ({ input, ctx }) => {
        const conv = await getConversation(input.conversationId, ctx.user.id);
        if (!conv) throw new TRPCError({ code: "NOT_FOUND", message: "المحادثة غير موجودة" });
        return getConversationMessages(input.conversationId);
      }),
  }),

  // ==================== Agent (Streaming) ====================
  agent: router({
    chat: protectedProcedure
      .input(z.object({
        conversationId: z.number(),
        content: z.string(),
        model: z.string().optional(),
        attachments: z.array(z.object({
          name: z.string(), url: z.string(), type: z.string(), size: z.number(), extractedText: z.string().optional(),
        })).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const conv = await getConversation(input.conversationId, ctx.user.id);
        if (!conv) throw new TRPCError({ code: "NOT_FOUND", message: "المحادثة غير موجودة" });

        await addMessage({
          conversationId: input.conversationId,
          role: "user",
          content: input.content,
          attachments: input.attachments,
        });

        const history = await getConversationMessages(input.conversationId);
        const llmMessages: Message[] = history
          .filter(m => m.role !== "system")
          .slice(-20)
          .map(m => ({ role: m.role as "user" | "assistant", content: m.content }));

        const aiResponse = await invokeLLM(llmMessages, conv.systemPrompt ?? undefined);

        const aiMsgId = await addMessage({
          conversationId: input.conversationId,
          role: "assistant",
          content: aiResponse,
        });

        await incrementUsage(ctx.user.id);

        return { messageId: aiMsgId, content: aiResponse };
      }),

    // Generate code files from a prompt
    generate: protectedProcedure
      .input(z.object({
        prompt: z.string(),
        category: z.string().optional(),
        model: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);

        // ── Smart System Prompt based on category ──────────────────
        const FILE_FORMAT = `⚠️ CRITICAL FORMAT: Your response MUST use this exact format:
===FILE:filename.ext===
complete file content
===ENDFILE===
(repeat for multiple files)
===SUMMARY===
brief description
===ENDSUMMARY===

Start with ===FILE: on the FIRST line. No text before it. No markdown. No JSON.`;

        const DESIGN_STANDARDS = `
FONTS + ICONS (always include in HTML):
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">

COLOR SCHEME: --primary:#667eea; --secondary:#764ba2; --bg:#0a0a0f; --card:#1a1a2e;
IMAGES: https://loremflickr.com/800/450/{topic}?lock=N (vary N per image)
LAYOUT: RTL, responsive, professional dark theme, hover effects, animations`;

        const categoryPrompts: Record<string, string> = {
          web: `${FILE_FORMAT}\n\nYou are an elite full-stack web developer at HAYO AI.\nGenerate a COMPLETE, single-file HTML website.\n${DESIGN_STANDARDS}\nMinimum: navbar + hero + 6-card grid + sidebar + footer + dark/light toggle + hamburger menu.`,

          scripts: `${FILE_FORMAT}\n\nYou are a Python/Shell scripting expert at HAYO AI.\nGenerate complete, runnable scripts.\nUse ===FILE:script.py=== or ===FILE:script.sh=== as appropriate.\nInclude error handling, logging, and clear comments in Arabic.\nMake scripts practical and immediately useful.`,

          data: `${FILE_FORMAT}\n\nYou are a data science expert at HAYO AI.\nGenerate Python scripts for data analysis, visualization, and processing.\nUse: pandas, numpy, matplotlib, seaborn (import them).\nInclude sample data generation if needed.\nAdd Arabic comments explaining each step.`,

          ai: `${FILE_FORMAT}\n\nYou are an AI/ML engineer at HAYO AI.\nGenerate complete Python code for AI/ML tasks.\nUse: scikit-learn, tensorflow, pytorch, transformers as needed.\nInclude data preprocessing, model training, evaluation.\nAdd clear Arabic comments.`,

          api: `${FILE_FORMAT}\n\nYou are a backend API developer at HAYO AI.\nGenerate complete API code (Express.js, Flask, or FastAPI).\nInclude routes, middleware, error handling, validation.\nAdd Swagger/OpenAPI documentation.\nUse ===FILE:server.py=== or ===FILE:server.js===.`,

          mobile: `${FILE_FORMAT}\n\nYou are a React Native/Expo mobile developer at HAYO AI.\nGenerate ===FILE:App.tsx=== with complete React Native code.\nUse: react-native core, expo-status-bar, @expo/vector-icons, expo-linear-gradient.\nSingle file, useState for navigation, professional UI.`,

          defense: `${FILE_FORMAT}\n\nYou are a cybersecurity DEFENSE educator at HAYO AI.\nGenerate educational security tools and scripts for DEFENSIVE purposes:\n- Network monitoring and anomaly detection\n- Log analysis and SIEM rules\n- Firewall configuration generators\n- Input validation and sanitization libraries\n- WAF rule generators\n- Security audit checklists\n- Encryption/hashing utilities\nAll code must be clearly educational with Arabic comments explaining security concepts.`,

          forensics: `${FILE_FORMAT}\n\nYou are a digital forensics educator at HAYO AI.\nGenerate educational forensics tools:\n- Log parser and analyzer\n- File metadata extractor\n- Network packet analyzer (educational)\n- Timeline reconstruction tools\n- Hash verification utilities\nAll code educational with Arabic explanations.`,

          pentest: `${FILE_FORMAT}\n\nYou are a cybersecurity EDUCATION specialist at HAYO AI.\nGenerate EDUCATIONAL content that explains security concepts:\n- Explain how common vulnerabilities work (SQL injection, XSS, CSRF) with PSEUDOCODE examples\n- Generate DEFENSIVE code (input validation, CSP headers, parameterized queries)\n- Create CTF-style challenges with solutions\n- Build security testing checklists\nAll content must be clearly educational. Include Arabic explanations of each concept.\nFocus on DEFENSE: how to PREVENT and DETECT attacks.`,

          network: `${FILE_FORMAT}\n\nYou are a network engineering educator at HAYO AI.\nGenerate network tools and scripts:\n- Network scanner (ping sweep, port check)\n- DNS lookup utilities\n- Bandwidth monitoring\n- Network configuration generators\n- Firewall rule builders\nEducational with Arabic comments.`,

          general: `${FILE_FORMAT}\n\nYou are an elite developer at HAYO AI.\nAnalyze the user's request and generate the most appropriate code.\nFor web requests: generate HTML with ${DESIGN_STANDARDS}\nFor scripts: generate Python/JS/Shell\nFor other: use the best language for the task.\nAlways professional, complete, and immediately runnable.`,
        };

        const systemPrompt = categoryPrompts[input.category || "general"] || categoryPrompts.general;

        const raw = await invokeLLM(
          [{ role: "user", content: input.prompt }],
          systemPrompt,
          undefined,
          input.model
        );

        // Debug: log raw LLM response prefix
        console.log(`[generate] raw len=${raw.length} hasDelim=${raw.includes("===FILE:")} hasEndFile=${raw.includes("===ENDFILE===")} start=${JSON.stringify(raw.slice(0, 300))}`);

        // Parse delimited file format  ===FILE:name===...===ENDFILE===
        const parseDelimited = (text: string): { files: { name: string; content: string }[]; summary: string } => {
          const files: { name: string; content: string }[] = [];
          const parts = text.split("===FILE:");
          for (let i = 1; i < parts.length; i++) {
            const hEnd = parts[i].indexOf("===");
            if (hEnd === -1) continue;
            const name = parts[i].slice(0, hEnd).trim();
            const rest = parts[i].slice(hEnd + 3);
            // ===ENDFILE=== is optional — model sometimes omits it
            const cEnd = rest.indexOf("===ENDFILE===");
            const cEndSummary = rest.indexOf("===SUMMARY===");
            // Use ENDFILE if present, else SUMMARY boundary, else whole rest
            const actualEnd = cEnd !== -1 ? cEnd : (cEndSummary !== -1 ? cEndSummary : rest.length);
            const fileContent = rest.startsWith("\n") ? rest.slice(1, actualEnd) : rest.slice(0, actualEnd);
            if (name && fileContent.trim().length > 0) files.push({ name, content: fileContent });
          }
          const si = text.indexOf("===SUMMARY===");
          const ei = text.indexOf("===ENDSUMMARY===");
          const summary = si !== -1 && ei !== -1 ? text.slice(si + 13, ei).trim() : "";
          return { files, summary };
        };

        // Strategy 1: delimited format — ENDFILE is optional (model sometimes omits it)
        if (raw.includes("===FILE:")) {
          const result = parseDelimited(raw);
          if (result.files.length > 0) { console.log(`[generate] Strategy 1 OK: ${result.files.map(f=>f.name).join(",")}`); return result; }
        }

        // Strategy 2: JSON (fallback for non-compliant responses)
        try {
          let jsonStr = raw.trim();
          const jmatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
          if (jmatch) jsonStr = jmatch[1].trim();
          const si = jsonStr.indexOf("{"); const ei = jsonStr.lastIndexOf("}");
          if (si !== -1 && ei !== -1) jsonStr = jsonStr.slice(si, ei + 1);
          const parsed = JSON.parse(jsonStr);
          if (parsed.files?.length > 0) {
            console.log(`[generate] Strategy 2 JSON OK: ${parsed.files.map((f: {name:string}) => f.name).join(",")}`);
            return { files: parsed.files as { name: string; content: string }[], summary: (parsed.summary || "") as string };
          }
        } catch { /* continue */ }

        // Strategy 3: raw IS HTML
        const trimmedRaw = raw.trim();
        if (/^<!doctype\s+html/i.test(trimmedRaw) || /^<html[\s>]/i.test(trimmedRaw)) {
          console.log(`[generate] Strategy 3: raw IS HTML`);
          return { files: [{ name: "index.html", content: raw }], summary: "\u062a\u0645 \u0625\u0646\u0634\u0627\u0621 \u0627\u0644\u0645\u0644\u0641" };
        }

        // Strategy 4: HTML buried inside response - extract and unescape JSON sequences
        const htmlBlock = raw.match(/<!DOCTYPE\s+html[\s\S]*?<\/html>/i);
        if (htmlBlock) {
          const htmlContent = htmlBlock[0]
            .replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\r/g, "\r")
            .replace(/\\"/g, '"').replace(/\\\\/g, "\\");
          console.log(`[generate] Strategy 4: HTML buried`);
          return { files: [{ name: "index.html", content: htmlContent }], summary: "\u062a\u0645 \u0625\u0646\u0634\u0627\u0621 \u0627\u0644\u0645\u0644\u0641" };
        }

        // Strategy 5: any markdown code block
        const codeBlock = raw.match(/```(?:html|css|js|py)?\s*([\s\S]*?)```/s);
        if (codeBlock && codeBlock[1].trim().length > 100) {
          const cbContent = codeBlock[1].trim();
          const isHtml = /^<!doctype|^<html/i.test(cbContent) || /<\/html>/i.test(cbContent);
          const isPy = input.category === "python";
          const ext = isPy ? "py" : isHtml ? "html" : "html"; // default html for web requests
          console.log(`[generate] Strategy 5: ext=${ext} isHtml=${isHtml} category=${input.category}`);
          return { files: [{ name: `index.${ext}`, content: codeBlock[1] }], summary: "\u062a\u0645 \u0625\u0646\u0634\u0627\u0621 \u0627\u0644\u0645\u0644\u0641" };
        }

        // Final fallback: always html unless python; detect from content
        const rawHasHtml = /<html[\s>]|<!DOCTYPE\s+html/i.test(raw);
        const ext = input.category === "python" ? "py" : "html";
        console.log(`[generate] Final fallback: ext=${ext} rawHasHtml=${rawHasHtml} category=${input.category} rawLen=${raw.length} rawStart=${JSON.stringify(raw.slice(0, 200))}`);
        return { files: [{ name: `output.${ext}`, content: rawHasHtml ? raw : raw }], summary: "\u062a\u0645 \u0625\u0646\u0634\u0627\u0621 \u0627\u0644\u0645\u0644\u0641" };
      }),

    // Fix/improve existing code using AI
    fix: protectedProcedure
      .input(z.object({
        code: z.string(),
        fileName: z.string(),
        category: z.string().optional(),
        model: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);

        const systemPrompt = `أنت مراجع كود خبير من HAYO AI. مهمتك تحليل الكود وإصلاح أي أخطاء أو تحسينه.

يجب أن تُرجع ردّك فقط بتنسيق JSON صحيح:
{
  "fixedCode": "الكود المُصحَّح كاملاً",
  "fixes": ["وصف الإصلاح الأول", "وصف الإصلاح الثاني"]
}

لا تُرجع أي نص خارج كتلة JSON.`;

        const userMsg = `اسم الملف: ${input.fileName}\n\nالكود:\n\`\`\`\n${input.code}\n\`\`\``;
        const raw = await invokeLLM([{ role: "user", content: userMsg }], systemPrompt, undefined, input.model);

        let jsonStr = raw.trim();
        const jsonMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
        if (jsonMatch) jsonStr = jsonMatch[1].trim();
        const startIdx = jsonStr.indexOf("{");
        const endIdx = jsonStr.lastIndexOf("}");
        if (startIdx !== -1 && endIdx !== -1) jsonStr = jsonStr.slice(startIdx, endIdx + 1);

        try {
          const parsed = JSON.parse(jsonStr);
          return {
            fixedCode: (parsed.fixedCode || input.code) as string,
            fixes: (parsed.fixes || ["تم مراجعة الكود"]) as string[],
          };
        } catch {
          return { fixedCode: input.code, fixes: ["لم يتم العثور على أخطاء واضحة"] };
        }
      }),

    // ── 4-Model Pipeline: plan→code→review→enhance ───────────────
    pipeline: protectedProcedure
      .input(z.object({
        prompt: z.string().min(1).max(8000),
        category: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);

        const parseJson = (raw: string): Record<string, unknown> => {
          let s = raw.trim();
          const block = s.match(/```(?:json)?\s*([\s\S]*?)```/);
          if (block) s = block[1].trim();
          const start = s.indexOf("{"); const end = s.lastIndexOf("}");
          if (start !== -1 && end !== -1) s = s.slice(start, end + 1);
          return JSON.parse(s);
        };

        // ── Phase 1: ANALYZE (Claude Sonnet) ──────────────────────────
        const planSystem = `أنت كبير مهندسي البرمجيات في HAYO AI. مهمتك تحليل الطلب وإنشاء خطة تفصيلية.
أُرجع JSON فقط (بدون أي نص خارجه):
{
  "projectName": "اسم المشروع",
  "description": "وصف موجز",
  "files": [
    { "name": "اسم_الملف.ext", "purpose": "الغرض من الملف", "priority": 1 }
  ],
  "techStack": ["التقنيات المستخدمة"],
  "notes": "ملاحظات للمطوّر"
}`;
        const planRaw = await invokeLLM(
          [{ role: "user", content: `طلب المستخدم: ${input.prompt}` }],
          planSystem, undefined, "claude-sonnet"
        );
        let plan: { projectName: string; description: string; files: { name: string; purpose: string; priority: number }[]; techStack: string[]; notes: string };
        try {
          plan = parseJson(planRaw) as typeof plan;
          if (!Array.isArray(plan.files) || plan.files.length === 0) throw new Error("empty plan");
        } catch {
          plan = {
            projectName: "مشروع",
            description: input.prompt,
            files: [{ name: "index.html", purpose: "الصفحة الرئيسية", priority: 1 }],
            techStack: ["HTML", "CSS", "JS"],
            notes: "",
          };
        }

        // ── Phase 2: CODE (Claude Opus) ─────────────────────────────
        const codeSystem = `You are an elite web developer at HAYO AI. Generate a COMPLETE, PRODUCTION-QUALITY website.

Use EXACTLY this format for files (NO JSON):
===FILE:filename.ext===
complete file content here
===ENDFILE===
===SUMMARY===
description
===ENDSUMMARY===

MANDATORY QUALITY STANDARDS:
1. IMAGES — Use loremflickr.com (always loads, topic-specific, no API key):
   Hero:  https://loremflickr.com/1400/600/{topic}
   Cards: https://loremflickr.com/800/450/{topic}?lock=1 (vary ?lock=2,3,4...per card)
   Match keyword to actual content — never generic unrelated images

2. FONTS + ICONS — Always include:
   <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;600;700;900&family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
   <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">

3. COLOR & DESIGN:
   Dark theme: --bg-dark:#0a0a0f; --bg-card:#1a1a2e; --primary:#667eea; --secondary:#764ba2;
   NO white backgrounds — use dark/gradient backgrounds
   Cards with border-radius:16px, box-shadow, hover transform:translateY(-8px)

4. LAYOUT: sticky navbar + hero grid (60/40) + 6-card grid + sidebar + footer

5. CONTENT: minimum 7 FULL articles with detailed Arabic text, proper categories, real headlines

6. INTERACTIVITY: hamburger menu, dark/light toggle, category filters`;

        const codePrompt = `Project plan:
- Name: ${plan.projectName}
- Description: ${plan.description}
- Tech: ${plan.techStack?.join(", ")}
- Files needed: ${plan.files.map((f) => `${f.name} (${f.purpose})`).join(", ")}
- Notes: ${plan.notes || "none"}

User request: ${input.prompt}

Generate complete, immediately runnable code for each file.`;
        const codeRaw = await invokeLLM(
          [{ role: "user", content: codePrompt }],
          codeSystem, undefined, "claude-opus"
        );
        let generatedFiles: { name: string; content: string }[] = [];
        let summary = "";

        // Try delimiter format first
        if (codeRaw.includes("===FILE:") && codeRaw.includes("===ENDFILE===")) {
          const parts = codeRaw.split("===FILE:");
          for (let i = 1; i < parts.length; i++) {
            const hEnd = parts[i].indexOf("===");
            if (hEnd === -1) continue;
            const name = parts[i].slice(0, hEnd).trim();
            const rest = parts[i].slice(hEnd + 3);
            const cEnd = rest.indexOf("===ENDFILE===");
            if (cEnd === -1) continue;
            const fileContent = rest.startsWith("\n") ? rest.slice(1, cEnd) : rest.slice(0, cEnd);
            if (name) generatedFiles.push({ name, content: fileContent });
          }
          const si = codeRaw.indexOf("===SUMMARY===");
          const ei = codeRaw.indexOf("===ENDSUMMARY===");
          summary = si !== -1 && ei !== -1 ? codeRaw.slice(si + 13, ei).trim() : plan.description;
        }

        // Fallback: try JSON
        if (generatedFiles.length === 0) {
          try {
            const parsed = parseJson(codeRaw) as { files: typeof generatedFiles; summary: string };
            generatedFiles = parsed.files || [];
            summary = parsed.summary || "";
          } catch {
            const ext = input.category === "python" ? "py" : "html";
            generatedFiles = [{ name: `index.${ext}`, content: codeRaw }];
            summary = plan.description;
          }
        }

        // ── Phase 3: REVIEW (DeepSeek) ────────────────────────────────
        const reviewSystem = `أنت مراجع كود خبير. راجع الكود المُنشأ وأصلح أي أخطاء أو ثغرات أو نقص.
أُرجع JSON فقط:
{
  "files": [
    { "name": "اسم_الملف.ext", "content": "الكود المُصحَّح الكامل" }
  ],
  "fixes": ["وصف الإصلاح 1", "وصف الإصلاح 2"]
}`;
        const reviewPrompt = `راجع هذه الملفات وأصلح أي مشاكل:
${generatedFiles.map((f) => `### ${f.name}\n\`\`\`\n${f.content.slice(0, 3000)}\n\`\`\``).join("\n\n")}

تأكد من:
- لا يوجد أخطاء نحوية أو منطقية
- الملفات متسقة ومترابطة
- الكود قابل للتشغيل مباشرة`;
        const reviewRaw = await invokeLLM(
          [{ role: "user", content: reviewPrompt }],
          reviewSystem, undefined, "deepseek-coder"
        );
        try {
          const reviewed = parseJson(reviewRaw) as { files: typeof generatedFiles; fixes: string[] };
          if (reviewed.files?.length > 0) generatedFiles = reviewed.files;
        } catch { /* keep existing files */ }

        // ── Phase 4: ENHANCE (Gemini) ─────────────────────────────────
        const enhanceSystem = `أنت مهندس برمجيات متخصص في إنهاء المشاريع. أضف الملفات الضرورية الناقصة مثل README و package.json والـ config files.
أُرجع JSON فقط:
{
  "additionalFiles": [
    { "name": "اسم_الملف.ext", "content": "المحتوى الكامل" }
  ],
  "improvements": ["تحسين 1", "تحسين 2"]
}`;
        const existingNames = generatedFiles.map((f) => f.name).join(", ");
        const enhancePrompt = `المشروع: ${plan.projectName}
الملفات الموجودة: ${existingNames}

أضف فقط الملفات الضرورية الناقصة (README.md، package.json إذا لزم، .gitignore، إلخ). لا تكرر الملفات الموجودة.`;
        const enhanceRaw = await invokeLLM(
          [{ role: "user", content: enhancePrompt }],
          enhanceSystem, undefined, "gemini-pro"
        );
        try {
          const enhanced = parseJson(enhanceRaw) as { additionalFiles: typeof generatedFiles; improvements: string[] };
          if (enhanced.additionalFiles?.length > 0) {
            const existingSet = new Set(generatedFiles.map((f) => f.name));
            for (const af of enhanced.additionalFiles) {
              if (!existingSet.has(af.name) && af.content) {
                generatedFiles.push(af);
                existingSet.add(af.name);
              }
            }
          }
        } catch { /* keep existing files */ }

        return {
          files: generatedFiles,
          summary: summary || plan.description,
          plan: {
            projectName: plan.projectName,
            techStack: plan.techStack,
            description: plan.description,
          },
        };
      }),

    // ── War Room: Run all 4 models in parallel on same prompt ────
    warRoom: protectedProcedure
      .input(z.object({ prompt: z.string().min(1).max(5000) }))
      .mutation(async ({ input, ctx }) => {
        const creditCheck = await checkCredits(ctx.user.id, "war_room");
        if (!creditCheck.allowed) {
          throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: creditCheck.message || "نفدت نقاطك اليومية" });
        }
        await deductCredits(ctx.user.id, "war_room");

        const providers: AIProvider[] = ["claude", "gpt4", "gemini", "geminiPro", "deepseek"];
        const systemPrompt = "أنت مساعد ذكاء اصطناعي متقدم. أجب بشكل مفيد ودقيق ومنظم. استخدم Markdown للتنسيق. تكلم بنفس لغة المستخدم.";

        const results = await Promise.allSettled(
          providers.map(async (provider) => {
            const available = isProviderAvailable(provider);
            if (!available && provider !== "claude") {
              return {
                provider,
                providerName: PROVIDER_CONFIGS[provider].name,
                icon: PROVIDER_CONFIGS[provider].icon,
                color: PROVIDER_CONFIGS[provider].color,
                content: "",
                duration: 0,
                available: false,
                error: "API key not configured. Add to Replit Secrets to enable.",
              };
            }
            const result = await callProvider(provider, systemPrompt, input.prompt);
            return {
              provider,
              providerName: PROVIDER_CONFIGS[provider].name,
              icon: PROVIDER_CONFIGS[provider].icon,
              color: PROVIDER_CONFIGS[provider].color,
              content: result.content,
              duration: result.duration,
              available: true,
              error: null,
            };
          })
        );

        return results.map((r, i) => {
          if (r.status === "fulfilled") return r.value;
          return {
            provider: providers[i],
            providerName: PROVIDER_CONFIGS[providers[i]].name,
            icon: PROVIDER_CONFIGS[providers[i]].icon,
            color: PROVIDER_CONFIGS[providers[i]].color,
            content: "",
            duration: 0,
            available: false,
            error: (r.reason as Error).message,
          };
        });
      }),

    // ── Multi-model single chat (for Chat page model switcher) ───
    multiChat: protectedProcedure
      .input(z.object({
        message: z.string().min(1),
        provider: z.enum(["claude", "gpt4", "gemini", "deepseek"]).default("claude"),
        systemPrompt: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);
        const systemPrompt = input.systemPrompt ||
          "أنت مساعد ذكاء اصطناعي من HAYO AI. أجب بشكل مفيد ودقيق. استخدم Markdown للتنسيق. تكلم بنفس لغة المستخدم.";
        const result = await callProvider(input.provider, systemPrompt, input.message);
        return {
          content: result.content,
          provider: result.provider,
          duration: result.duration,
        };
      }),

    // ── Fix ALL files in a project using dual-AI ─────────────────
    fixAll: protectedProcedure
      .input(z.object({
        files: z.array(z.object({ name: z.string(), content: z.string() })),
        description: z.string().optional(),
        model: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);

        const fixedFiles: Array<{ name: string; content: string; fixes: string[] }> = [];
        const allFixes: string[] = [];

        for (const file of input.files) {
          const systemPrompt = `أنت مراجع كود خبير. أصلح هذا الملف وحسّنه.
${input.description ? `تعليمات إضافية: ${input.description}` : ""}
أُرجع JSON فقط: {"fixedCode": "الكود المُصحَّح كاملاً", "fixes": ["إصلاح 1", "إصلاح 2"]}`;

          try {
            const raw = await invokeLLM(
              [{ role: "user", content: `ملف: ${file.name}\n\n\`\`\`\n${file.content.slice(0, 15000)}\n\`\`\`` }],
              systemPrompt, undefined, input.model || "claude-sonnet"
            );

            let jsonStr = raw.trim();
            const jm = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
            if (jm) jsonStr = jm[1].trim();
            const si = jsonStr.indexOf("{"); const ei = jsonStr.lastIndexOf("}");
            if (si !== -1 && ei !== -1) jsonStr = jsonStr.slice(si, ei + 1);

            const parsed = JSON.parse(jsonStr);
            fixedFiles.push({
              name: file.name,
              content: parsed.fixedCode || file.content,
              fixes: parsed.fixes || [],
            });
            allFixes.push(...(parsed.fixes || []).map((f: string) => `${file.name}: ${f}`));
          } catch {
            fixedFiles.push({ name: file.name, content: file.content, fixes: [] });
          }
        }

        return { files: fixedFiles, totalFixes: allFixes.length, fixes: allFixes };
      }),

    // ── Get all providers with availability status ────────────────
    getProviders: publicProcedure.query(() => {
      return Object.values(PROVIDER_CONFIGS).map(p => ({
        id: p.id,
        name: p.name,
        model: p.model,
        icon: p.icon,
        color: p.color,
        role: p.role,
        available: isProviderAvailable(p.id as AIProvider),
      }));
    }),
  }),

  // ==================== EA Factory (MQ4/MQ5) ====================
  eaFactory: router({
    // Analyze uploaded MQ4/MQ5 files with user notes
    analyze: protectedProcedure
      .input(z.object({
        files: z.array(z.object({ name: z.string(), content: z.string() })).min(1).max(100),
        userNotes: z.string().max(5000).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);
        const { analyzeFiles } = await import("./services/ea-factory.js");
        return analyzeFiles(input.files, input.userNotes || "");
      }),

    // Generate code from MULTIPLE strategies combined + user notes
    generate: protectedProcedure
      .input(z.object({
        strategies: z.array(z.object({
          id: z.string(), name: z.string(), description: z.string(), category: z.string().optional(),
          filesUsed: z.array(z.string()), indicators: z.array(z.string()),
          filters: z.array(z.string()).optional(),
          entryLogic: z.string(), exitLogic: z.string(), riskManagement: z.string(),
          timeframe: z.string(), confidence: z.number(), complexity: z.string().optional(),
        })).min(1),
        sourceFiles: z.array(z.object({ name: z.string(), content: z.string() })),
        platform: z.enum(["mq4", "mq5"]),
        outputType: z.enum(["ea", "indicator"]),
        userNotes: z.string().max(5000).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);
        const { generateCode } = await import("./services/ea-factory.js");
        return generateCode(input.strategies, input.sourceFiles, input.platform, input.outputType, input.userNotes || "");
      }),

    // Generate custom code from free-text + user notes
    generateCustom: protectedProcedure
      .input(z.object({
        prompt: z.string().min(10).max(5000),
        sourceFiles: z.array(z.object({ name: z.string(), content: z.string() })),
        platform: z.enum(["mq4", "mq5"]),
        outputType: z.enum(["ea", "indicator"]),
        userNotes: z.string().max(5000).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);
        const { generateCustomCode } = await import("./services/ea-factory.js");
        return generateCustomCode(input.prompt, input.sourceFiles, input.platform, input.outputType, input.userNotes || "");
      }),

    // Fix compile errors from MetaEditor
    fixErrors: protectedProcedure
      .input(z.object({
        code: z.string().min(50),
        errors: z.string().min(5),
        platform: z.enum(["mq4", "mq5"]),
        outputType: z.enum(["ea", "indicator"]),
        userNotes: z.string().max(5000).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);
        const { fixCompileErrors } = await import("./services/ea-factory.js");
        return fixCompileErrors(input.code, input.errors, input.platform, input.outputType, input.userNotes || "");
      }),
  }),

  // ==================== Trading (OANDA Forex) ====================
  trading: router({
    // Test OANDA connection
    testOanda: protectedProcedure
      .input(z.object({
        apiToken: z.string(),
        accountId: z.string(),
        environment: z.enum(["practice", "live"]).default("practice"),
      }))
      .mutation(async ({ input }) => {
        const { testConnection } = await import("./services/oanda-trading.js");
        return testConnection(input);
      }),

    // Get account summary
    accountInfo: protectedProcedure
      .input(z.object({
        apiToken: z.string(),
        accountId: z.string(),
        environment: z.enum(["practice", "live"]).default("practice"),
      }))
      .query(async ({ input }) => {
        const { getAccountInfo } = await import("./services/oanda-trading.js");
        return getAccountInfo(input);
      }),

    // Get live prices
    prices: protectedProcedure
      .input(z.object({
        apiToken: z.string(),
        accountId: z.string(),
        environment: z.enum(["practice", "live"]).default("practice"),
        instruments: z.array(z.string()),
      }))
      .query(async ({ input }) => {
        const { getPrices } = await import("./services/oanda-trading.js");
        return getPrices(input, input.instruments);
      }),

    // Place order
    placeOrder: protectedProcedure
      .input(z.object({
        apiToken: z.string(),
        accountId: z.string(),
        environment: z.enum(["practice", "live"]).default("practice"),
        instrument: z.string(),
        units: z.number(),
        type: z.enum(["MARKET", "LIMIT", "STOP"]).default("MARKET"),
        price: z.number().optional(),
        stopLossPrice: z.number().optional(),
        takeProfitPrice: z.number().optional(),
      }))
      .mutation(async ({ input }) => {
        const { placeOrder } = await import("./services/oanda-trading.js");
        return placeOrder(
          { apiToken: input.apiToken, accountId: input.accountId, environment: input.environment },
          { instrument: input.instrument, units: input.units, type: input.type, price: input.price, stopLossPrice: input.stopLossPrice, takeProfitPrice: input.takeProfitPrice }
        );
      }),

    // Get open positions
    positions: protectedProcedure
      .input(z.object({
        apiToken: z.string(),
        accountId: z.string(),
        environment: z.enum(["practice", "live"]).default("practice"),
      }))
      .query(async ({ input }) => {
        const { getOpenPositions } = await import("./services/oanda-trading.js");
        return getOpenPositions(input);
      }),

    // Get open trades
    trades: protectedProcedure
      .input(z.object({
        apiToken: z.string(),
        accountId: z.string(),
        environment: z.enum(["practice", "live"]).default("practice"),
      }))
      .query(async ({ input }) => {
        const { getOpenTrades } = await import("./services/oanda-trading.js");
        return getOpenTrades(input);
      }),

    // Close trade
    closeTrade: protectedProcedure
      .input(z.object({
        apiToken: z.string(),
        accountId: z.string(),
        environment: z.enum(["practice", "live"]).default("practice"),
        tradeId: z.string(),
      }))
      .mutation(async ({ input }) => {
        const { closeTrade } = await import("./services/oanda-trading.js");
        return closeTrade(input, input.tradeId);
      }),

    // Auto-execute signal from TradingAnalysis page
    autoExecute: protectedProcedure
      .input(z.object({
        apiToken: z.string(),
        accountId: z.string(),
        environment: z.enum(["practice", "live"]).default("practice"),
        pair: z.string(),
        direction: z.enum(["BUY", "SELL"]),
        confidence: z.number().min(0).max(100),
        stopLoss: z.number().optional(),
        takeProfit: z.number().optional(),
        riskPercent: z.number().min(0.1).max(5).default(1),
      }))
      .mutation(async ({ input }) => {
        const { autoExecuteSignal } = await import("./services/oanda-trading.js");
        return autoExecuteSignal(
          { apiToken: input.apiToken, accountId: input.accountId, environment: input.environment },
          { pair: input.pair, direction: input.direction, confidence: input.confidence, stopLoss: input.stopLoss, takeProfit: input.takeProfit },
          input.riskPercent
        );
      }),

    getCandles: protectedProcedure
      .input(z.object({
        pair: z.enum(["EURUSD", "USDJPY", "GBPUSD", "GBPJPY", "USDCHF", "AUDUSD", "NZDUSD", "USDCAD", "EURGBP", "EURJPY", "EURCHF", "AUDCAD", "XAUUSD", "XAGUSD", "BTCUSD", "ETHUSD", "USOIL", "US30"]),
        interval: z.enum(["1min", "5min", "15min", "30min", "1h"]).default("1h"),
        outputsize: z.number().min(5).max(200).default(120),
      }))
      .mutation(async ({ input }) => {
        const symbolMap: Record<string, string> = {
          EURUSD: "EUR/USD", USDJPY: "USD/JPY", GBPUSD: "GBP/USD",
          GBPJPY: "GBP/JPY", USDCHF: "USD/CHF", AUDUSD: "AUD/USD",
          NZDUSD: "NZD/USD", USDCAD: "USD/CAD",
          EURGBP: "EUR/GBP", EURJPY: "EUR/JPY", EURCHF: "EUR/CHF", AUDCAD: "AUD/CAD",
          XAUUSD: "XAU/USD", XAGUSD: "XAG/USD",
          BTCUSD: "BTC/USD", ETHUSD: "ETH/USD",
          USOIL: "CL", US30: "DJIA",
        };

        const symbol = symbolMap[input.pair] || input.pair;
        const data = await fetchTwelveData(`https://api.twelvedata.com/time_series?symbol=${encodeURIComponent(symbol)}&interval=${input.interval}&outputsize=${input.outputsize}&apikey=__API_KEY__`);
        if (data.status === "error" || !data.values) {
          throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: data.message || "فشل جلب البيانات" });
        }

        const candles = [...data.values].reverse().map((c: any) => {
          const o = parseFloat(c.open), h = parseFloat(c.high), l = parseFloat(c.low), cl = parseFloat(c.close);
          if (isNaN(o) || isNaN(h) || isNaN(l) || isNaN(cl)) return null;
          return { time: Math.floor(new Date(c.datetime).getTime() / 1000), open: o, high: h, low: l, close: cl };
        }).filter(Boolean);

        return { candles, symbol, interval: input.interval };
      }),
  }),

  // ==================== Automation ====================
  automation: router({
    githubPush: protectedProcedure
      .input(z.object({
        repoName: z.string(),
        files: z.array(z.object({ path: z.string(), content: z.string() })),
        description: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // First try to get token from user's saved integrations in DB
        const userIntegrations = await getUserIntegrations(ctx.user.id);
        const githubIntegration = userIntegrations.find(
          (i) => i.provider === "github" && i.isActive && i.accessToken
        );
        const githubToken = githubIntegration?.accessToken ?? process.env.GITHUB_TOKEN;
        if (!githubToken) {
          throw new TRPCError({
            code: "PRECONDITION_FAILED",
            message: "يرجى ربط حسابك بـ GitHub من صفحة التكاملات أولاً",
          });
        }
        // GitHub API integration
        const headers = {
          "Authorization": `token ${githubToken}`,
          "Accept": "application/vnd.github.v3+json",
          "Content-Type": "application/json",
        };
        // Create repo
        const createRes = await fetch("https://api.github.com/user/repos", {
          method: "POST",
          headers,
          body: JSON.stringify({ name: input.repoName, description: input.description || "", auto_init: true }),
        });
        if (!createRes.ok && createRes.status !== 422) {
          throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "فشل إنشاء المستودع على GitHub" });
        }
        const repoData = await createRes.json() as { html_url?: string; full_name?: string };
        const repoUrl = repoData?.html_url || `https://github.com/${input.repoName}`;
        return { message: `تم رفع ${input.files.length} ملف(ات) إلى GitHub`, repoUrl };
      }),

    vercelDeploy: protectedProcedure
      .input(z.object({
        projectName: z.string(),
        files: z.array(z.object({ path: z.string(), content: z.string() })),
      }))
      .mutation(async () => {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: "يرجى ربط حسابك بـ Vercel من صفحة التكاملات أولاً",
        });
      }),
  }),

  // ==================== AI (frontend alias for agent.chat) ====================
  ai: router({
    chat: protectedProcedure
      .input(z.object({
        conversationId: z.number(),
        message: z.string(),
        model: z.string().optional(),
        attachments: z.array(z.object({
          name: z.string(),
          url: z.string(),
          type: z.string(),
          size: z.number(),
          extractedText: z.string().optional(),
        })).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // ── Enforce daily message limit (admin/owner bypass) ──
        if (ctx.user.role !== "admin") {
          const { db } = await import("@workspace/db");
          const { subscriptionCodes, subscriptionPlans, usageRecords } = await import("@workspace/db/schema");
          const { eq, and, gt, isNotNull } = await import("drizzle-orm");
          const now = new Date();
          const todayStr = now.toISOString().slice(0, 10); // "YYYY-MM-DD"
          const activeSub = await db.select({ plan: subscriptionPlans })
            .from(subscriptionCodes)
            .innerJoin(subscriptionPlans, eq(subscriptionCodes.planId, subscriptionPlans.id))
            .where(and(eq(subscriptionCodes.usedBy, ctx.user.id), isNotNull(subscriptionCodes.usedAt), gt(subscriptionCodes.expiresAt, now)))
            .limit(1);
          const dailyLimit = activeSub[0]?.plan?.dailyMessageLimit ?? 10;
          if (dailyLimit !== -1) {
            const usage = await db.select().from(usageRecords)
              .where(and(eq(usageRecords.userId, ctx.user.id), eq(usageRecords.date, todayStr)))
              .limit(1);
            const todayCount = usage[0]?.messageCount || 0;
            if (todayCount >= dailyLimit) {
              throw new TRPCError({ code: "FORBIDDEN", message: `وصلت إلى الحد اليومي (${dailyLimit} رسالة). اشترك لرفع الحد.` });
            }
          }
        }

        const conv = await getConversation(input.conversationId, ctx.user.id);
        if (!conv) throw new TRPCError({ code: "NOT_FOUND", message: "المحادثة غير موجودة" });

        await addMessage({
          conversationId: input.conversationId,
          role: "user",
          content: input.message,
          attachments: input.attachments,
        });

        const history = await getConversationMessages(input.conversationId);
        const llmMessages: Message[] = history
          .filter(m => m.role !== "system")
          .slice(-20)
          .map(m => ({ role: m.role as "user" | "assistant", content: m.content }));

        const aiResponse = await invokeLLM(llmMessages, conv.systemPrompt ?? undefined);

        const aiMsgId = await addMessage({
          conversationId: input.conversationId,
          role: "assistant",
          content: aiResponse,
        });

        await incrementUsage(ctx.user.id);

        return { messageId: aiMsgId, content: aiResponse, steps: undefined };
      }),
  }),

  // ==================== Files ====================
  files: router({
    list: protectedProcedure.query(async ({ ctx }) => getUserFiles(ctx.user.id)),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => getFileById(input.id)),

    save: protectedProcedure
      .input(z.object({
        fileName: z.string(),
        fileKey: z.string(),
        fileUrl: z.string(),
        mimeType: z.string(),
        fileSize: z.number(),
        extractedText: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await saveUploadedFile({ ...input, userId: ctx.user.id });
        return { id };
      }),

    // Alias: frontend uses files.upload
    upload: protectedProcedure
      .input(z.object({
        fileName: z.string(),
        fileKey: z.string().optional(),
        fileUrl: z.string().optional(),
        mimeType: z.string().optional(),
        fileSize: z.number().optional(),
        extractedText: z.string().optional(),
        content: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await saveUploadedFile({
          userId: ctx.user.id,
          fileName: input.fileName,
          fileKey: input.fileKey || `local_${Date.now()}`,
          fileUrl: input.fileUrl || "",
          mimeType: input.mimeType || "application/octet-stream",
          fileSize: input.fileSize || 0,
          extractedText: input.extractedText || input.content,
        });
        return { id, url: input.fileUrl || "" };
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await deleteFile(input.id, ctx.user.id);
        return { success: true };
      }),
  }),

  // ==================== Plans & Subscriptions ====================
  plans: router({
    list: publicProcedure.query(() => getActivePlans()),
    get: publicProcedure.input(z.object({ id: z.number() })).query(({ input }) => getPlanById(input.id)),

    mySubscription: protectedProcedure.query(async ({ ctx }) => {
      const sub = await getUserActiveSubscription(ctx.user.id);
      if (!sub) return null;
      const plan = await getPlanById(sub.planId);
      return { subscription: sub, plan };
    }),
  }),

  // ==================== Usage & Credits ====================
  usage: router({
    today: protectedProcedure.query(async ({ ctx }) => getOrCreateDailyUsage(ctx.user.id)),
    daily: protectedProcedure.query(async ({ ctx }) => getOrCreateDailyUsage(ctx.user.id)),
    subscription: protectedProcedure.query(async ({ ctx }) => {
      // Admin/owner users always get unlimited owner plan
      if (ctx.user.role === "admin") {
        return {
          subscription: null,
          plan: {
            id: 0,
            name: "owner",
            displayName: "مالك المنصة",
            description: "وصول غير محدود لجميع الميزات",
            priceMonthly: 0,
            dailyMessageLimit: 999999,
            maxFileUploadMB: 1000,
            maxCodeExecutionSec: 9999,
            canUseWebSearch: true,
            dailyCreditLimit: -1,
          },
        };
      }
      const sub = await getUserActiveSubscription(ctx.user.id);
      if (!sub) return null;
      const plan = await getPlanById(sub.planId);
      return { subscription: sub, plan };
    }),
    // Credits overview: today's usage + plan limit
    credits: protectedProcedure.query(async ({ ctx }) => {
      // Admin/owner: unlimited credits
      if (ctx.user.role === "admin") {
        return { used: 0, dailyLimit: 999999, remaining: 999999, isUnlimited: true };
      }
      const { db } = await import("@workspace/db");
      const { subscriptionCodes, subscriptionPlans } = await import("@workspace/db/schema");
      const { eq, and, isNotNull, gt } = await import("drizzle-orm");
      const usage = await getOrCreateDailyUsage(ctx.user.id);
      const used = usage.creditsUsed ?? 0;
      const now = new Date();
      const rows = await db.select({ dailyCreditLimit: subscriptionPlans.dailyCreditLimit })
        .from(subscriptionCodes)
        .innerJoin(subscriptionPlans, eq(subscriptionCodes.planId, subscriptionPlans.id))
        .where(and(eq(subscriptionCodes.usedBy, ctx.user.id), isNotNull(subscriptionCodes.usedAt), gt(subscriptionCodes.expiresAt, now)))
        .limit(1);
      const dailyLimit = rows[0]?.dailyCreditLimit ?? 5;
      const realLimit = dailyLimit === -1 ? 9999 : dailyLimit;
      return {
        used,
        dailyLimit: realLimit,
        remaining: Math.max(0, realLimit - used),
        costMap: CREDIT_COSTS,
      };
    }),
  }),

  // ==================== Integrations ====================
  integrations: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      const rows = await getUserIntegrations(ctx.user.id);
      return rows.map((r: any) => ({
        provider: r.provider || r.serviceId,
        isActive: r.status === "connected" || r.isActive,
        connectedAt: r.connectedAt || r.createdAt,
        info: (() => {
          const m = r.metadata;
          if (!m) return {};
          if (typeof m === "object") return m;
          try { return JSON.parse(m); } catch { return {}; }
        })(),
      }));
    }),

    // Test connection without saving
    test: protectedProcedure
      .input(z.object({ provider: z.string(), credentials: z.record(z.string()) }))
      .mutation(async ({ input }) => {
        const { testConnection } = await import("./services/integration-tester");
        return testConnection(input.provider, input.credentials);
      }),

    // Test + save connection
    connect: protectedProcedure
      .input(z.object({ provider: z.string(), credentials: z.record(z.string()) }))
      .mutation(async ({ input, ctx }) => {
        const { testConnection } = await import("./services/integration-tester");
        const { encrypt } = await import("./services/encryption");

        // 1. Test the connection first
        const test = await testConnection(input.provider, input.credentials);
        if (!test.success) {
          throw new TRPCError({ code: "BAD_REQUEST", message: test.error || "فشل الاتصال" });
        }

        // 2. Encrypt credentials and save
        const encrypted: Record<string, string> = {};
        for (const [k, v] of Object.entries(input.credentials)) {
          encrypted[k] = encrypt(v);
        }

        await connectIntegration({
          userId: ctx.user.id,
          provider: input.provider,
          accessToken: JSON.stringify(encrypted),
          metadata: test.info || undefined,
        });

        return { success: true, info: test.info };
      }),

    disconnect: protectedProcedure
      .input(z.object({ provider: z.string() }))
      .mutation(async ({ input, ctx }) => {
        await disconnectIntegration(ctx.user.id, input.provider);
        return { success: true };
      }),
  }),

  // ==================== API Keys ====================
  apiKeys: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      const { db } = await import("@workspace/db");
      const { apiKeys } = await import("@workspace/db/schema");
      const { eq } = await import("drizzle-orm");
      return db.select().from(apiKeys).where(eq(apiKeys.userId, ctx.user.id));
    }),

    create: protectedProcedure
      .input(z.object({ name: z.string() }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { apiKeys } = await import("@workspace/db/schema");
        const { randomBytes } = await import("crypto");
        const rawKey = randomBytes(24).toString("hex");
        const key = `hayo_${rawKey}`;
        const keyPrefix = key.slice(0, 12);
        const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year
        const result = await db.insert(apiKeys).values({
          userId: ctx.user.id,
          label: input.name,
          keyHash: key,
          keyPrefix,
          planId: (ctx.user as any).planId ?? 1,
          isActive: true,
          expiresAt,
        }).returning();
        return { ...result[0], key };
      }),

    revoke: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { apiKeys } = await import("@workspace/db/schema");
        const { eq, and } = await import("drizzle-orm");
        await db.update(apiKeys)
          .set({ isActive: false })
          .where(and(eq(apiKeys.id, input.id), eq(apiKeys.userId, ctx.user.id)));
        return { success: true };
      }),
  }),

  // ==================== Telegram ====================
  telegram: router({
    getBot: protectedProcedure.query(async ({ ctx }) => {
      const { db } = await import("@workspace/db");
      const { telegramBots } = await import("@workspace/db/schema");
      const { eq } = await import("drizzle-orm");
      const bots = await db.select().from(telegramBots).where(eq(telegramBots.userId, ctx.user.id)).limit(1);
      return bots[0] || null;
    }),

    connect: protectedProcedure
      .input(z.object({ botToken: z.string(), botUsername: z.string().optional() }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { telegramBots } = await import("@workspace/db/schema");
        const { eq } = await import("drizzle-orm");

        // 1. Verify the token with Telegram API
        const botInfoRes = await fetch(`https://api.telegram.org/bot${input.botToken}/getMe`);
        const botInfo = await botInfoRes.json() as any;
        if (!botInfo.ok) throw new Error(`توكن البوت غير صحيح: ${botInfo.description || "خطأ غير معروف"}`);

        const botUsername = input.botUsername || botInfo.result?.username || null;

        // 2. Register the webhook with Telegram
        const domain = process.env.REPLIT_DOMAINS || process.env.REPLIT_DEV_DOMAIN;
        if (domain) {
          const webhookUrl = `https://${domain}/api/telegram/webhook/${ctx.user.id}`;
          const webhookRes = await fetch(`https://api.telegram.org/bot${input.botToken}/setWebhook`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: webhookUrl, allowed_updates: ["message", "edited_message"] }),
          });
          const webhookData = await webhookRes.json() as any;
          if (!webhookData.ok) console.warn("[Telegram] Webhook setup warning:", webhookData.description);
        }

        // 3. Save to DB
        const existing = await db.select().from(telegramBots).where(eq(telegramBots.userId, ctx.user.id)).limit(1);
        if (existing[0]) {
          await db.update(telegramBots).set({ botToken: input.botToken, botUsername, isActive: true }).where(eq(telegramBots.userId, ctx.user.id));
        } else {
          await db.insert(telegramBots).values({ userId: ctx.user.id, botToken: input.botToken, botUsername, isActive: true });
        }
        return { success: true, botUsername };
      }),

    disconnect: protectedProcedure.mutation(async ({ ctx }) => {
      const { db } = await import("@workspace/db");
      const { telegramBots } = await import("@workspace/db/schema");
      const { eq } = await import("drizzle-orm");
      const bots = await db.select().from(telegramBots).where(eq(telegramBots.userId, ctx.user.id)).limit(1);
      if (bots[0]?.botToken) {
        await fetch(`https://api.telegram.org/bot${bots[0].botToken}/deleteWebhook`, { method: "POST" }).catch(() => {});
      }
      await db.update(telegramBots).set({ isActive: false }).where(eq(telegramBots.userId, ctx.user.id));
      return { success: true };
    }),

    toggleChat: protectedProcedure
      .input(z.object({ enabled: z.boolean() }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { telegramBots } = await import("@workspace/db/schema");
        const { eq } = await import("drizzle-orm");
        await db.update(telegramBots).set({ isActive: input.enabled }).where(eq(telegramBots.userId, ctx.user.id));
        return { success: true };
      }),

    updateSettings: protectedProcedure
      .input(z.object({ welcomeMessage: z.string().optional(), systemPrompt: z.string().optional() }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { telegramBots } = await import("@workspace/db/schema");
        const { eq } = await import("drizzle-orm");
        await db.update(telegramBots).set({ welcomeMessage: input.welcomeMessage || null, systemPrompt: input.systemPrompt || null }).where(eq(telegramBots.userId, ctx.user.id));
        return { success: true };
      }),
  }),

  // ==================== Admin ====================
  admin: router({
    stats: adminProcedure.query(() => getAdminStats()),

    users: router({
      list: adminProcedure.query(() => getAllUsers()),
    }),

    plans: router({
      list: adminProcedure.query(() => getActivePlans()),
      update: adminProcedure
        .input(z.object({
          id: z.number(),
          displayName: z.string().optional(),
          priceMonthly: z.number().optional(),
          priceYearly: z.number().optional(),
          dailyMessageLimit: z.number().optional(),
          monthlyMessageLimit: z.number().optional(),
          isActive: z.boolean().optional(),
        }))
        .mutation(async ({ input }) => {
          const { db } = await import("@workspace/db");
          const { subscriptionPlans } = await import("@workspace/db/schema");
          const { eq } = await import("drizzle-orm");
          const { id, ...data } = input;
          await db.update(subscriptionPlans).set({ ...data, updatedAt: new Date() }).where(eq(subscriptionPlans.id, id));
          return { success: true };
        }),
    }),

    subscriptions: router({
      list: adminProcedure.query(async () => {
        const { db } = await import("@workspace/db");
        const { subscriptions } = await import("@workspace/db/schema");
        return db.select().from(subscriptions);
      }),

      // Get subscribers with user+plan info
      getSubscribers: adminProcedure.query(async () => {
        const { db } = await import("@workspace/db");
        const { subscriptions, users, subscriptionPlans } = await import("@workspace/db/schema");
        const { eq, desc } = await import("drizzle-orm");
        const now = new Date();
        const rows = await db.select({
          id: subscriptions.id,
          userId: subscriptions.userId,
          planId: subscriptions.planId,
          status: subscriptions.status,
          startDate: subscriptions.startDate,
          endDate: subscriptions.endDate,
          userName: users.name,
          userEmail: users.email,
          planName: subscriptionPlans.name,
          planDisplayName: subscriptionPlans.displayName,
        })
          .from(subscriptions)
          .leftJoin(users, eq(subscriptions.userId, users.id))
          .leftJoin(subscriptionPlans, eq(subscriptions.planId, subscriptionPlans.id))
          .orderBy(desc(subscriptions.startDate));

        return rows.map(r => ({
          ...r,
          user: { name: r.userName, email: r.userEmail },
          plan: { name: r.planName, displayName: r.planDisplayName },
          isExpired: r.endDate ? r.endDate < now : false,
          daysLeft: r.endDate ? Math.max(0, Math.ceil((r.endDate.getTime() - now.getTime()) / 86400000)) : null,
        }));
      }),

      create: adminProcedure
        .input(z.object({ userId: z.number(), planId: z.number(), durationDays: z.number().default(30) }))
        .mutation(async ({ input }) => {
          const { db } = await import("@workspace/db");
          const { subscriptions } = await import("@workspace/db/schema");
          const now = new Date();
          const endDate = new Date(now.getTime() + input.durationDays * 86400000);
          await db.insert(subscriptions).values({
            userId: input.userId,
            planId: input.planId,
            status: "active",
            startDate: now,
            endDate,
          });
          return { success: true };
        }),

      cancel: adminProcedure
        .input(z.object({ subscriptionId: z.number() }))
        .mutation(async ({ input }) => {
          const { db } = await import("@workspace/db");
          const { subscriptions } = await import("@workspace/db/schema");
          const { eq } = await import("drizzle-orm");
          await db.update(subscriptions).set({ status: "cancelled" }).where(eq(subscriptions.id, input.subscriptionId));
          return { success: true };
        }),

      extend: adminProcedure
        .input(z.object({ subscriptionId: z.number(), extraDays: z.number() }))
        .mutation(async ({ input }) => {
          const { db } = await import("@workspace/db");
          const { subscriptions } = await import("@workspace/db/schema");
          const { eq } = await import("drizzle-orm");
          const sub = await db.select().from(subscriptions).where(eq(subscriptions.id, input.subscriptionId)).limit(1);
          if (!sub[0]) throw new TRPCError({ code: "NOT_FOUND", message: "الاشتراك غير موجود" });
          const base = sub[0].endDate && sub[0].endDate > new Date() ? sub[0].endDate : new Date();
          const newEnd = new Date(base.getTime() + input.extraDays * 86400000);
          await db.update(subscriptions).set({ endDate: newEnd, status: "active" }).where(eq(subscriptions.id, input.subscriptionId));
          return { success: true };
        }),
    }),

    apiKeys: router({
      list: adminProcedure.query(async () => {
        const { db } = await import("@workspace/db");
        const { apiKeys, users } = await import("@workspace/db/schema");
        const { eq } = await import("drizzle-orm");
        return db.select({
          id: apiKeys.id,
          name: apiKeys.label,
          keyHash: apiKeys.keyHash,
          isActive: apiKeys.isActive,
          createdAt: apiKeys.createdAt,
          userId: apiKeys.userId,
          userName: users.name,
          userEmail: users.email,
        }).from(apiKeys).leftJoin(users, eq(apiKeys.userId, users.id));
      }),

      revoke: adminProcedure
        .input(z.object({ id: z.number() }))
        .mutation(async ({ input }) => {
          const { db } = await import("@workspace/db");
          const { apiKeys } = await import("@workspace/db/schema");
          const { eq } = await import("drizzle-orm");
          await db.update(apiKeys).set({ isActive: false }).where(eq(apiKeys.id, input.id));
          return { success: true };
        }),
    }),
  }),

  // ==================== Subscription Codes ====================
  subscriptions: router({
    // Get user's active subscription (from codes or plans)
    myActive: protectedProcedure.query(async ({ ctx }) => {
      const { db } = await import("@workspace/db");
      const { subscriptionCodes, subscriptionPlans } = await import("@workspace/db/schema");
      const { eq, and, gt, isNotNull } = await import("drizzle-orm");
      const now = new Date();
      const active = await db.select({
        code: subscriptionCodes,
        plan: subscriptionPlans,
      })
        .from(subscriptionCodes)
        .innerJoin(subscriptionPlans, eq(subscriptionCodes.planId, subscriptionPlans.id))
        .where(and(
          eq(subscriptionCodes.usedBy, ctx.user.id),
          isNotNull(subscriptionCodes.usedAt),
          gt(subscriptionCodes.expiresAt, now),
        ))
        .orderBy(subscriptionCodes.expiresAt)
        .limit(1);
      return active[0] || null;
    }),

    // Redeem a subscription code
    redeem: protectedProcedure
      .input(z.object({ code: z.string().trim().toUpperCase() }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { subscriptionCodes, subscriptionPlans } = await import("@workspace/db/schema");
        const { eq, and, isNull } = await import("drizzle-orm");
        const now = new Date();

        const result = await db.select({ code: subscriptionCodes, plan: subscriptionPlans })
          .from(subscriptionCodes)
          .innerJoin(subscriptionPlans, eq(subscriptionCodes.planId, subscriptionPlans.id))
          .where(and(
            eq(subscriptionCodes.code, input.code),
            eq(subscriptionCodes.isActive, true),
            isNull(subscriptionCodes.usedBy),
          ))
          .limit(1);

        const entry = result[0];
        if (!entry) {
          throw new TRPCError({ code: "NOT_FOUND", message: "الكود غير صحيح أو مستخدم مسبقاً" });
        }

        const expiresAt = new Date(now.getTime() + entry.code.durationDays * 24 * 60 * 60 * 1000);
        await db.update(subscriptionCodes)
          .set({ usedBy: ctx.user.id, usedAt: now, expiresAt, isActive: false })
          .where(eq(subscriptionCodes.id, entry.code.id));

        return { success: true, plan: entry.plan, expiresAt };
      }),

    // Check usage limits
    checkLimit: protectedProcedure.query(async ({ ctx }) => {
      // Admin/owner: always unlimited
      if (ctx.user.role === "admin") {
        return { todayCount: 0, dailyLimit: -1, planName: "owner", isLimited: false, hasActiveSub: true };
      }
      const { db } = await import("@workspace/db");
      const { subscriptionCodes, subscriptionPlans, usageRecords } = await import("@workspace/db/schema");
      const { eq, and, gt, isNotNull } = await import("drizzle-orm");
      const now = new Date();
      const todayStr = now.toISOString().slice(0, 10); // "YYYY-MM-DD"

      // Check active subscription code
      const activeSub = await db.select({ plan: subscriptionPlans })
        .from(subscriptionCodes)
        .innerJoin(subscriptionPlans, eq(subscriptionCodes.planId, subscriptionPlans.id))
        .where(and(eq(subscriptionCodes.usedBy, ctx.user.id), isNotNull(subscriptionCodes.usedAt), gt(subscriptionCodes.expiresAt, now)))
        .limit(1);

      const plan = activeSub[0]?.plan || { dailyMessageLimit: 10, monthlyMessageLimit: 100, name: "free" };

      const usage = await db.select().from(usageRecords)
        .where(and(eq(usageRecords.userId, ctx.user.id), eq(usageRecords.date, todayStr)))
        .limit(1);

      const todayCount = usage[0]?.messageCount || 0;
      const dailyLimit = plan.dailyMessageLimit === -1 ? Infinity : plan.dailyMessageLimit;
      const isLimited = todayCount >= dailyLimit;

      return {
        todayCount,
        dailyLimit: plan.dailyMessageLimit,
        planName: plan.name,
        isLimited,
        hasActiveSub: activeSub.length > 0,
      };
    }),

    // ── Stripe: Create Checkout Session ──────────────────────────
    createStripeCheckout: protectedProcedure
      .input(z.object({
        planName: z.enum(["starter", "pro", "business"]),
        billingPeriod: z.enum(["monthly", "yearly"]).default("monthly"),
      }))
      .mutation(async ({ input, ctx }) => {
        const stripeKey = process.env.STRIPE_SECRET_KEY;
        if (!stripeKey) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Stripe غير مُعد حالياً. استخدم الدفع اليدوي." });

        const { db } = await import("@workspace/db");
        const { subscriptionPlans } = await import("@workspace/db/schema");
        const { eq } = await import("drizzle-orm");

        const planRows = await db.select().from(subscriptionPlans).where(eq(subscriptionPlans.name, input.planName)).limit(1);
        const plan = planRows[0];
        if (!plan) throw new TRPCError({ code: "NOT_FOUND", message: "الخطة غير موجودة" });

        const price = input.billingPeriod === "yearly" ? plan.priceYearly : plan.priceMonthly;
        const durationDays = input.billingPeriod === "yearly" ? 365 : 30;

        const Stripe = (await import("stripe")).default;
        const stripe = new Stripe(stripeKey, { apiVersion: "2024-04-10" as any });

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          mode: "payment",
          customer_email: ctx.user.email || undefined,
          line_items: [{
            price_data: {
              currency: "usd",
              product_data: {
                name: `HAYO AI — ${plan.displayName} (${input.billingPeriod === "yearly" ? "سنوي" : "شهري"})`,
                description: plan.description || "",
              },
              unit_amount: price,
            },
            quantity: 1,
          }],
          metadata: {
            userId: String(ctx.user.id),
            planName: input.planName,
            billingPeriod: input.billingPeriod,
            durationDays: String(durationDays),
          },
          success_url: `${process.env.APP_URL || "https://hayo-ai.com"}/payment?status=success&session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.APP_URL || "https://hayo-ai.com"}/pricing`,
        });

        return { url: session.url, sessionId: session.id };
      }),

    // ── Stripe: Verify Payment & Activate ────────────────────────
    verifyStripePayment: protectedProcedure
      .input(z.object({ sessionId: z.string() }))
      .mutation(async ({ input, ctx }) => {
        const stripeKey = process.env.STRIPE_SECRET_KEY;
        if (!stripeKey) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Stripe غير مُعد" });

        const Stripe = (await import("stripe")).default;
        const stripe = new Stripe(stripeKey, { apiVersion: "2024-04-10" as any });
        const session = await stripe.checkout.sessions.retrieve(input.sessionId);

        if (session.payment_status !== "paid") {
          throw new TRPCError({ code: "BAD_REQUEST", message: "الدفع لم يكتمل بعد" });
        }

        const planName = session.metadata?.planName;
        const durationDays = parseInt(session.metadata?.durationDays || "30");
        if (!planName) throw new TRPCError({ code: "BAD_REQUEST", message: "بيانات الخطة مفقودة" });

        const { db } = await import("@workspace/db");
        const { subscriptionCodes, subscriptionPlans } = await import("@workspace/db/schema");
        const { eq } = await import("drizzle-orm");
        const { randomBytes } = await import("crypto");

        const planRows = await db.select().from(subscriptionPlans).where(eq(subscriptionPlans.name, planName)).limit(1);
        if (!planRows[0]) throw new TRPCError({ code: "NOT_FOUND", message: "الخطة غير موجودة" });

        const code = `STRIPE-${randomBytes(4).toString("hex").toUpperCase()}`;
        const now = new Date();
        const expiresAt = new Date(now.getTime() + durationDays * 24 * 60 * 60 * 1000);

        await db.insert(subscriptionCodes).values({
          code,
          planId: planRows[0].id,
          durationDays,
          isActive: false,
          usedBy: ctx.user.id,
          usedAt: now,
          expiresAt,
          note: `Stripe: ${session.id} | ${session.customer_email || ""}`,
        });

        return { success: true, plan: planRows[0], expiresAt, code };
      }),
  }),

  // ==================== Islam Message (رسالة الإسلام) ====================
  islam: router({
    listSurahs: publicProcedure.query(async () => {
      const { listSurahs } = await import("./services/islam.js");
      return listSurahs();
    }),
    getSurah: publicProcedure.input(z.object({ number: z.number().min(1).max(114), edition: z.string().default("quran-uthmani") })).query(async ({ input }) => {
      const { getSurah } = await import("./services/islam.js");
      return getSurah(input.number, input.edition);
    }),
    getAyah: publicProcedure.input(z.object({ reference: z.string(), editions: z.string().default("quran-uthmani,ar.muyassar") })).query(async ({ input }) => {
      const { getAyah } = await import("./services/islam.js");
      return getAyah(input.reference, input.editions);
    }),
    searchQuran: publicProcedure.input(z.object({ query: z.string().min(2) })).mutation(async ({ input }) => {
      const { searchQuran } = await import("./services/islam.js");
      return searchQuran(input.query);
    }),
    getTafsir: publicProcedure.input(z.object({ surah: z.number(), ayah: z.number(), edition: z.string().default("ar-tafsir-al-tabari") })).query(async ({ input }) => {
      const { getTafsir } = await import("./services/islam.js");
      return getTafsir(input.surah, input.ayah, input.edition);
    }),
    listTafsirs: publicProcedure.query(async () => {
      const { listTafsirs } = await import("./services/islam.js");
      return listTafsirs();
    }),
    listHadithBooks: publicProcedure.query(async () => {
      const { listHadithBooks } = await import("./services/islam.js");
      return listHadithBooks();
    }),
    searchHadith: protectedProcedure.input(z.object({ query: z.string().min(3), book: z.string().default("all") })).mutation(async ({ input }) => {
      const { searchHadith } = await import("./services/islam.js");
      return searchHadith(input.query, input.book);
    }),
    compareMadhahib: protectedProcedure.input(z.object({ topic: z.string().min(5) })).mutation(async ({ input }) => {
      const { compareMadhahib } = await import("./services/islam.js");
      return compareMadhahib(input.topic);
    }),
    scientificMiracle: protectedProcedure.input(z.object({ topic: z.string().min(5) })).mutation(async ({ input }) => {
      const { scientificMiracle } = await import("./services/islam.js");
      return scientificMiracle(input.topic);
    }),
  }),

  // ==================== OSINT Intelligence Tools ====================
  osint: router({
    ipLookup: protectedProcedure
      .input(z.object({ ip: z.string().min(4).max(50) }))
      .mutation(async ({ input }) => {
        const { ipLookup } = await import("./services/osint.js");
        return ipLookup(input.ip);
      }),
    whoisLookup: protectedProcedure
      .input(z.object({ domain: z.string().min(3).max(200) }))
      .mutation(async ({ input }) => {
        const { whoisLookup } = await import("./services/osint.js");
        return whoisLookup(input.domain);
      }),
    dnsLookup: protectedProcedure
      .input(z.object({ domain: z.string().min(3).max(200), type: z.string().default("A") }))
      .mutation(async ({ input }) => {
        const { dnsLookup } = await import("./services/osint.js");
        return dnsLookup(input.domain, input.type);
      }),
    emailBreachCheck: protectedProcedure
      .input(z.object({ email: z.string().email() }))
      .mutation(async ({ input }) => {
        const { emailBreachCheck } = await import("./services/osint.js");
        return emailBreachCheck(input.email);
      }),
    usernameSearch: protectedProcedure
      .input(z.object({ username: z.string().min(2).max(50) }))
      .mutation(async ({ input }) => {
        const { usernameSearch } = await import("./services/osint.js");
        return usernameSearch(input.username);
      }),
    phoneLookup: protectedProcedure
      .input(z.object({ phone: z.string().min(5).max(20) }))
      .mutation(async ({ input }) => {
        const { phoneLookup } = await import("./services/osint.js");
        return phoneLookup(input.phone);
      }),
    techLookup: protectedProcedure
      .input(z.object({ url: z.string().min(3).max(200) }))
      .mutation(async ({ input }) => {
        const { techLookup } = await import("./services/osint.js");
        return techLookup(input.url);
      }),
    sslLookup: protectedProcedure
      .input(z.object({ domain: z.string().min(3).max(200) }))
      .mutation(async ({ input }) => {
        const { sslLookup } = await import("./services/osint.js");
        return sslLookup(input.domain);
      }),
    subdomainSearch: protectedProcedure
      .input(z.object({ domain: z.string().min(3).max(200) }))
      .mutation(async ({ input }) => {
        const { subdomainSearch } = await import("./services/osint.js");
        return subdomainSearch(input.domain);
      }),
    phoneLocalLookup: protectedProcedure
      .input(z.object({ phone: z.string().min(6).max(20) }))
      .mutation(async ({ input, ctx }) => {
        const { phoneLocalLookup, logOsintSearch } = await import("./services/osint.js");
        const result = await phoneLocalLookup(input.phone);
        await logOsintSearch(ctx.user.id, "phone_local", input.phone, result.totalResults);
        return result;
      }),
    coverageStats: protectedProcedure
      .query(async () => {
        const { getCoverageStats } = await import("./services/osint.js");
        return getCoverageStats();
      }),

    importStats: protectedProcedure
      .query(async () => {
        const { getImportStats } = await import("./services/osint-import.js");
        return getImportStats();
      }),

    importFromCSV: protectedProcedure
      .input(z.object({ csvContent: z.string().min(10), sourceName: z.string().min(1).max(100) }))
      .mutation(async ({ input }) => {
        const { importFromCSVContent } = await import("./services/osint-import.js");
        return importFromCSVContent(input.csvContent, input.sourceName);
      }),

    importFromGoogleDrive: protectedProcedure
      .input(z.object({ fileId: z.string().min(1), sourceName: z.string().optional() }))
      .mutation(async ({ input }) => {
        const { importFromGoogleDrive } = await import("./services/osint-import.js");
        return importFromGoogleDrive(input.fileId, input.sourceName || "");
      }),

    listGoogleDriveFiles: protectedProcedure
      .query(async () => {
        const { listGoogleDriveFiles } = await import("./services/osint-import.js");
        return listGoogleDriveFiles();
      }),

    importFromObjectStorage: protectedProcedure
      .input(z.object({ filePath: z.string().min(1), sourceName: z.string().optional() }))
      .mutation(async ({ input }) => {
        const { importFromObjectStorage } = await import("./services/osint-import.js");
        return importFromObjectStorage(input.filePath, input.sourceName || "");
      }),

    listObjectStorageFiles: protectedProcedure
      .query(async () => {
        const { listObjectStorageFiles } = await import("./services/osint-import.js");
        return listObjectStorageFiles();
      }),

    importFromSupabase: protectedProcedure
      .input(z.object({
        connectionUrl: z.string().min(10),
        tableName: z.string().min(1),
        sourceName: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { importFromSupabase } = await import("./services/osint-import.js");
        return importFromSupabase(input.connectionUrl, input.tableName, input.sourceName || "");
      }),

    listSupabaseTables: protectedProcedure
      .input(z.object({ connectionUrl: z.string().min(10) }))
      .mutation(async ({ input }) => {
        const { listSupabaseTables } = await import("./services/osint-import.js");
        return listSupabaseTables(input.connectionUrl);
      }),

    deleteBySource: protectedProcedure
      .input(z.object({ source: z.string().min(1) }))
      .mutation(async ({ input }) => {
        const { deleteContactsBySource } = await import("./services/osint-import.js");
        return deleteContactsBySource(input.source);
      }),

    clearAllContacts: protectedProcedure
      .mutation(async () => {
        const { clearAllContacts } = await import("./services/osint-import.js");
        return clearAllContacts();
      }),
  }),

  // ==================== Mind Map ====================
  mindMap: router({
    generate: protectedProcedure
      .input(z.object({
        idea: z.string().min(5).max(2000),
        depth: z.number().min(2).max(4).default(3),
        userNotes: z.string().max(2000).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);
        const { generateMindMap } = await import("./services/mindmap.js");
        return generateMindMap(input.idea, input.depth, input.userNotes || "");
      }),

    expand: protectedProcedure
      .input(z.object({
        node: z.any(),
        parentContext: z.string(),
      }))
      .mutation(async ({ input, ctx }) => {
        await incrementUsage(ctx.user.id);
        const { expandNode } = await import("./services/mindmap.js");
        return expandNode(input.node, input.parentContext);
      }),
  }),

  // ==================== System Maintenance (Admin) ====================
  maintenance: router({
    // Quick health scan
    healthCheck: adminProcedure.query(async () => {
      const { systemHealthCheck } = await import("./services/security.js");
      return systemHealthCheck();
    }),

    // Quick code scan (no AI)
    quickScan: adminProcedure.mutation(async () => {
      const { quickScan } = await import("./services/maintenance.js");
      const projectRoot = process.cwd();
      return quickScan(projectRoot);
    }),

    // Get project file structure
    projectStructure: adminProcedure.query(async () => {
      const { getProjectStructure } = await import("./services/maintenance.js");
      return getProjectStructure(process.cwd());
    }),

    // AI deep diagnosis — full or specific files
    aiDiagnose: adminProcedure
      .input(z.object({
        files: z.array(z.string()).optional(),
        scope: z.enum(["all", "frontend", "backend", "routes", "services"]).default("all"),
        userNote: z.string().max(2000).optional(),
      }))
      .mutation(async ({ input }) => {
        const { aiDiagnose, getProjectStructure } = await import("./services/maintenance.js");
        const root = process.cwd();
        let files = input.files || [];

        if (files.length === 0) {
          const structure = getProjectStructure(root);
          const scopeFilter: Record<string, string> = {
            all: "src/",
            frontend: "src/pages/",
            backend: "src/hayo/",
            routes: "src/routes/",
            services: "src/hayo/services/",
          };
          const prefix = scopeFilter[input.scope] || "src/";
          files = structure.files.filter(f => f.path.startsWith(prefix)).slice(0, 10).map(f => f.path);
        }

        return aiDiagnose(files, root, input.userNote || "");
      }),

    // AI fix specific file + problem — with optional auto-apply
    aiFix: adminProcedure
      .input(z.object({
        filePath: z.string(),
        problem: z.string().min(5).max(2000),
        autoApply: z.boolean().default(false),
      }))
      .mutation(async ({ input }) => {
        const { aiFix } = await import("./services/maintenance.js");
        return aiFix(input.filePath, process.cwd(), input.problem, input.autoApply);
      }),

    // Read any file content (admin full access)
    readFile: adminProcedure
      .input(z.object({ filePath: z.string() }))
      .query(async ({ input }) => {
        const { readFile } = await import("./services/maintenance.js");
        return readFile(input.filePath, process.cwd());
      }),

    // Batch fix multiple files
    batchFix: adminProcedure
      .input(z.object({
        fixes: z.array(z.object({ file: z.string(), problem: z.string() })).min(1).max(10),
        autoApply: z.boolean().default(false),
      }))
      .mutation(async ({ input }) => {
        const { batchAiFix } = await import("./services/maintenance.js");
        return batchAiFix(input.fixes, process.cwd(), input.autoApply);
      }),

    // Restore file from backup
    restoreBackup: adminProcedure
      .input(z.object({ backupPath: z.string(), originalPath: z.string() }))
      .mutation(async ({ input }) => {
        const { restoreBackup } = await import("./services/maintenance.js");
        return restoreBackup(input.backupPath, input.originalPath, process.cwd());
      }),

    // 🚀 Executive auto-execute: scan → diagnose → fix all automatically
    autoExecute: adminProcedure
      .input(z.object({
        scope: z.enum(["all", "frontend", "backend", "services"]).default("all"),
      }))
      .mutation(async ({ input }) => {
        const { autoExecute } = await import("./services/maintenance.js");
        return autoExecute(process.cwd(), input.scope);
      }),
  }),

  // ==================== Admin - Codes ====================
  // (added to admin router via separate top-level for readability)
  codes: router({
    // Generate a new subscription code (admin only)
    generate: adminProcedure
      .input(z.object({
        planId: z.number(),
        durationDays: z.number().default(30),
        note: z.string().optional(),
        count: z.number().min(1).max(50).default(1),
      }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { subscriptionCodes } = await import("@workspace/db/schema");
        const { randomBytes } = await import("crypto");

        const generated: string[] = [];
        for (let i = 0; i < input.count; i++) {
          const code = `HAYO-${randomBytes(3).toString("hex").toUpperCase()}-${randomBytes(3).toString("hex").toUpperCase()}`;
          await db.insert(subscriptionCodes).values({
            code,
            planId: input.planId,
            durationDays: input.durationDays,
            createdBy: ctx.user.id,
            note: input.note || null,
            isActive: true,
          });
          generated.push(code);
        }
        return { codes: generated };
      }),

    // List all codes (admin only)
    list: adminProcedure.query(async () => {
      const { db } = await import("@workspace/db");
      const { subscriptionCodes, subscriptionPlans, users } = await import("@workspace/db/schema");
      const { eq, desc } = await import("drizzle-orm");
      return db.select({
        id: subscriptionCodes.id,
        code: subscriptionCodes.code,
        planId: subscriptionCodes.planId,
        durationDays: subscriptionCodes.durationDays,
        note: subscriptionCodes.note,
        isActive: subscriptionCodes.isActive,
        usedAt: subscriptionCodes.usedAt,
        expiresAt: subscriptionCodes.expiresAt,
        createdAt: subscriptionCodes.createdAt,
        planName: subscriptionPlans.displayName,
        usedByEmail: users.email,
      })
        .from(subscriptionCodes)
        .leftJoin(subscriptionPlans, eq(subscriptionCodes.planId, subscriptionPlans.id))
        .leftJoin(users, eq(subscriptionCodes.usedBy, users.id))
        .orderBy(desc(subscriptionCodes.createdAt));
    }),

    // Delete/deactivate a code
    deactivate: adminProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        const { db } = await import("@workspace/db");
        const { subscriptionCodes } = await import("@workspace/db/schema");
        const { eq } = await import("drizzle-orm");
        await db.update(subscriptionCodes).set({ isActive: false }).where(eq(subscriptionCodes.id, input.id));
        return { success: true };
      }),
  }),

  // ==================== App Builds (EAS) ====================
  builds: router({
    // Create a new APK build
    create: protectedProcedure
      .input(z.object({
        appName: z.string().min(2).max(60),
        description: z.string().min(10).max(3000),
        generatedCode: z.string().min(50),
        iconUrl: z.string().url().optional(),
        embeddedData: z.array(z.object({ filename: z.string(), content: z.string() })).optional(),
        supabaseUrl: z.string().url().optional(),
        supabaseKey: z.string().optional(),
        customKeystoreBase64: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { appBuilds } = await import("@workspace/db/schema");

        // Insert record as pending
        const [build] = await db.insert(appBuilds).values({
          userId: ctx.user.id,
          appName: input.appName,
          description: input.description,
          generatedCode: input.generatedCode,
          status: "pending",
          platform: "android",
        }).returning();

        // Kick off the EAS build asynchronously with AI review + retry
        (async () => {
          const { eq } = await import("drizzle-orm");
          try {
            await db.update(appBuilds).set({ status: "submitting", updatedAt: new Date() }).where(eq(appBuilds.id, build.id));

            // Step 1: AI review code before submitting
            const { createExpoProject, submitEASBuildWithRetry, aiReviewAndFix } = await import("./services/eas-builder.js");

            // AI review and fix the code
            const review = await aiReviewAndFix(input.generatedCode);
            const fixedCode = review.fixedCode;

            const { projectDir, slug } = await createExpoProject(input.appName, fixedCode, input.iconUrl, {
              embeddedData: input.embeddedData,
              supabaseUrl: input.supabaseUrl,
              supabaseKey: input.supabaseKey,
              customKeystoreBase64: input.customKeystoreBase64,
            });

            // Step 2: Submit with retry (up to 2 retries with AI fixes)
            const result = await submitEASBuildWithRetry(projectDir, slug, fixedCode, 2);

            await db.update(appBuilds).set({
              status: "building",
              expoJobId: result.expoJobId,
              expoSlug: result.expoSlug,
              buildLogsUrl: result.buildLogsUrl,
              generatedCode: fs.existsSync(path.join(projectDir, "App.tsx"))
                ? fs.readFileSync(path.join(projectDir, "App.tsx"), "utf-8")
                : fixedCode,
              updatedAt: new Date(),
            }).where(eq(appBuilds.id, build.id));
          } catch (err: any) {
            await db.update(appBuilds).set({
              status: "errored",
              errorMessage: err?.message?.slice(0, 1000) || "خطأ غير معروف",
              updatedAt: new Date(),
            }).where(eq(appBuilds.id, build.id));
          }
        })();

        return { buildId: build.id };
      }),

    // Check & sync build status from EAS
    sync: protectedProcedure
      .input(z.object({ buildId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { appBuilds } = await import("@workspace/db/schema");
        const { eq, and } = await import("drizzle-orm");

        const [build] = await db.select().from(appBuilds)
          .where(and(eq(appBuilds.id, input.buildId), eq(appBuilds.userId, ctx.user.id)))
          .limit(1);

        if (!build) throw new Error("البناء غير موجود");
        if (!build.expoJobId) return build;
        if (build.status === "finished" || build.status === "errored" || build.status === "cancelled") return build;

        try {
          const { checkEASBuildStatus } = await import("./services/eas-builder.js");
          const status = await checkEASBuildStatus(build.expoJobId, build.expoSlug ?? undefined);
          console.log(`[builds.sync] Build #${input.buildId} EAS status:`, JSON.stringify(status));

          await db.update(appBuilds).set({
            status: status.status,
            downloadUrl: status.downloadUrl,
            errorMessage: status.errorMessage,
            updatedAt: new Date(),
          }).where(eq(appBuilds.id, input.buildId));

          const [updated] = await db.select().from(appBuilds).where(eq(appBuilds.id, input.buildId)).limit(1);
          return updated;
        } catch (syncErr: any) {
          console.error(`[builds.sync] Error syncing build #${input.buildId}:`, syncErr?.message);
          return build;
        }
      }),

    // Get single build
    get: protectedProcedure
      .input(z.object({ buildId: z.number() }))
      .query(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { appBuilds } = await import("@workspace/db/schema");
        const { eq, and } = await import("drizzle-orm");

        const [build] = await db.select().from(appBuilds)
          .where(and(eq(appBuilds.id, input.buildId), eq(appBuilds.userId, ctx.user.id)))
          .limit(1);
        return build || null;
      }),

    // List user builds
    list: protectedProcedure.query(async ({ ctx }) => {
      const { db } = await import("@workspace/db");
      const { appBuilds } = await import("@workspace/db/schema");
      const { eq, desc } = await import("drizzle-orm");

      return db.select().from(appBuilds)
        .where(eq(appBuilds.userId, ctx.user.id))
        .orderBy(desc(appBuilds.createdAt))
        .limit(50);
    }),

    // Delete a build record (user can only delete their own)
    delete: protectedProcedure
      .input(z.object({ buildId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { appBuilds } = await import("@workspace/db/schema");
        const { eq, and } = await import("drizzle-orm");
        await db.delete(appBuilds)
          .where(and(eq(appBuilds.id, input.buildId), eq(appBuilds.userId, ctx.user.id)));
        return { success: true };
      }),

    // Generate React Native code via AI
    generateCode: protectedProcedure
      .input(z.object({
        appName: z.string(),
        description: z.string(),
        model: z.enum(["claude", "deepseek"]).default("claude"),
      }))
      .mutation(async ({ input }) => {
        const systemPrompt = `أنت مطور React Native/Expo محترف من المستوى العالمي. مهمتك توليد كود تطبيق أندرويد كامل وقابل للتشغيل باستخدام Expo SDK 52.

القواعد الصارمة — التزم بها 100%:
1. أعد ملف App.tsx فقط — لا شرح، لا markdown، لا backticks، الكود مباشرة
2. الحزم المتاحة المثبّتة فعلاً — استخدم أي منها حسب الحاجة:
   - react-native: View, Text, StyleSheet, TouchableOpacity, FlatList, ScrollView, TextInput, Image, Modal, Switch, Animated, Alert, Dimensions, Platform, SafeAreaView, KeyboardAvoidingView, ActivityIndicator, Linking
   - expo-status-bar: import { StatusBar } from 'expo-status-bar'
   - @expo/vector-icons: Ionicons, MaterialIcons, FontAwesome, MaterialCommunityIcons, Feather
   - expo-clipboard: import * as Clipboard from 'expo-clipboard'
   - expo-linear-gradient: import { LinearGradient } from 'expo-linear-gradient'
   - expo-haptics: import * as Haptics from 'expo-haptics'
   - expo-blur: import { BlurView } from 'expo-blur'
   - @react-native-async-storage/async-storage: import AsyncStorage from '@react-native-async-storage/async-storage'
   - expo-file-system: import * as FileSystem from 'expo-file-system' ← لقراءة/كتابة ملفات
   - expo-sharing: import * as Sharing from 'expo-sharing' ← لمشاركة ملفات
   - expo-image-picker: import * as ImagePicker from 'expo-image-picker' ← لاختيار صور
   - expo-camera: import { CameraView, useCameraPermissions } from 'expo-camera' ← للكاميرا
   - expo-location: import * as Location from 'expo-location' ← للموقع GPS
   - expo-notifications: import * as Notifications from 'expo-notifications' ← للإشعارات
   - expo-device: import * as Device from 'expo-device'
   - expo-sensors: import { Accelerometer, Gyroscope } from 'expo-sensors'
   - expo-web-browser: import * as WebBrowser from 'expo-web-browser' ← لفتح روابط
   - expo-linking: import * as Linking from 'expo-linking'
   - React hooks: useState, useEffect, useRef, useCallback, useMemo
   - fetch() API: لجلب بيانات من الإنترنت (أخبار، طقس، API خارجية)
3. ممنوع: react-navigation, expo-router, أو حزم غير مذكورة أعلاه
4. كل شيء في ملف واحد App.tsx — النافذات المختلفة عبر useState وليس navigation
5. الكود TypeScript صحيح تماماً
6. تصميم احترافي فاخر: ألوان متناسقة، تدرجات، ظلال، انتقالات سلسة، RTL support
7. ابدأ بـ: import React, { ... } from 'react';
8. أضف تفاعلية حقيقية وكاملة — ليس واجهة ثابتة
9. إذا التطبيق يحتاج بيانات من الإنترنت: استخدم fetch() مع try/catch و loading state
10. إذا التطبيق يحتاج حفظ بيانات محلياً: استخدم AsyncStorage
11. قواعد لتجنب الـ Crash:
   - لا تستخدم setInterval/setTimeout خارج useEffect — نظّف دائماً في cleanup
   - لا تستخدم Animated.Value خارج useRef
   - ممنوع expo-font أو useFonts
   - خطوط آمنة فقط: 'sans-serif', 'serif', 'monospace'
   - StatusBar من expo-status-bar وليس react-native
   - Clipboard من expo-clipboard وليس react-native`;

        const userPrompt = `اسم التطبيق: ${input.appName}
الوصف التفصيلي: ${input.description}

المطلوب: كود App.tsx كامل لتطبيق React Native/Expo. أعد الكود فقط بدون أي شرح أو markdown.`;

        let code = "";

        if (input.model === "deepseek") {
          // DeepSeek via direct API (OpenAI-compatible)
          const deepseekKey = process.env.DEEPSEEK_API_KEY;
          if (!deepseekKey) throw new Error("DEEPSEEK_API_KEY غير مضبوط");
          const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${deepseekKey}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              model: "deepseek-chat",
              max_tokens: 8192,
              temperature: 0.2,
              messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: userPrompt },
              ],
            }),
          });
          if (!res.ok) {
            const errData = await res.json().catch(() => ({})) as any;
            throw new Error(`DeepSeek API error ${res.status}: ${errData?.error?.message || res.statusText}`);
          }
          const data = await res.json() as any;
          code = data.choices?.[0]?.message?.content || "";
        } else {
          // Claude — use createAnthropicClient which handles Replit proxy correctly
          const { createAnthropicClient } = await import("./llm.js");
          const anthropic = createAnthropicClient();
          const msg = await anthropic.messages.create({
            model: "claude-opus-4-5",   // أقوى نموذج Claude
            max_tokens: 8192,
            system: systemPrompt,
            messages: [{ role: "user", content: userPrompt }],
          });
          code = (msg.content[0] as any).text || "";
        }

        // Strip markdown code fences if present
        code = code.replace(/^```(?:tsx?|javascript|jsx|typescript)?\n?/i, "").replace(/\n?```\s*$/i, "").trim();

        // ── Post-process: remove crash-causing patterns ──────────────────────────
        // 1) Remove expo-font usage (causes crash when Ionicons.font is undefined or wrong)
        code = code.replace(/^import \* as Font from ['"]expo-font['"];?\n?/gm, "");
        code = code.replace(/^import \{[^}]*useFonts[^}]*\} from ['"]expo-font['"];?\n?/gm, "");
        // Remove Font.useFonts call and fontsLoaded variable
        code = code.replace(/const \[fontsLoaded[^\]]*\][^;]*;?\s*\n?/g, "");
        code = code.replace(/const fontsLoaded[^;]*;\s*\n?/g, "");
        // Remove "if (!fontsLoaded) return null;" guard
        code = code.replace(/if\s*\(!?fontsLoaded\)\s*\{?\s*return\s+null\s*;?\s*\}?\s*\n?/g, "");

        // 2) Replace deprecated react-native Clipboard with expo-clipboard
        if (/import \{ Clipboard \} from ['"]react-native['"]/.test(code)) {
          code = code.replace(/import \{ Clipboard \} from ['"]react-native['"]/g, "import * as Clipboard from 'expo-clipboard'");
          code = code.replace(/Clipboard\.getString\(\)/g, "Clipboard.getStringAsync()");
        }

        // 3) Remove unsupported fonts on Android (Arial, Helvetica, Georgia, Times New Roman, etc.)
        // These fonts don't exist on Android and cause crashes or broken text
        const unsafeFonts = ["Arial", "Helvetica", "Georgia", "Times New Roman", "Times", "Courier New", "Courier", "Verdana", "Tahoma", "Impact"];
        for (const font of unsafeFonts) {
          // Replace fontFamily: 'Arial' with fontFamily: 'sans-serif'
          code = code.replace(new RegExp(`fontFamily:\\s*['"]${font}['"]`, "g"), "fontFamily: 'sans-serif'");
        }

        if (!code || code.length < 50) {
          throw new Error("النموذج لم يُعِد كوداً كافياً. حاول مرة أخرى.");
        }

        return { code };
      }),

    // ── Upload existing project and build APK ────────────────────
    createFromUpload: protectedProcedure
      .input(z.object({
        appName: z.string().min(2).max(60),
        files: z.array(z.object({ name: z.string(), content: z.string() })).min(1),
        iconUrl: z.string().url().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { appBuilds } = await import("@workspace/db/schema");

        // Insert record
        const [build] = await db.insert(appBuilds).values({
          userId: ctx.user.id,
          appName: input.appName,
          description: `مشروع مرفوع (${input.files.length} ملف)`,
          generatedCode: input.files.find(f => f.name.includes("App.tsx") || f.name.includes("App.jsx"))?.content || "",
          status: "pending",
          platform: "android",
        }).returning();

        // Build async
        (async () => {
          const { eq } = await import("drizzle-orm");
          try {
            await db.update(appBuilds).set({ status: "submitting", updatedAt: new Date() }).where(eq(appBuilds.id, build.id));

            const { createExpoProjectFromUpload, submitEASBuildWithRetry } = await import("./services/eas-builder.js");
            const { projectDir, slug, fixLog } = await createExpoProjectFromUpload(input.files, input.appName, input.iconUrl);

            const result = await submitEASBuildWithRetry(projectDir, slug,
              fs.readFileSync(path.join(projectDir, "App.tsx"), "utf-8"), 2);

            await db.update(appBuilds).set({
              status: "building",
              expoJobId: result.expoJobId,
              expoSlug: result.expoSlug,
              buildLogsUrl: result.buildLogsUrl,
              generatedCode: fs.readFileSync(path.join(projectDir, "App.tsx"), "utf-8"),
              updatedAt: new Date(),
            }).where(eq(appBuilds.id, build.id));
          } catch (err: any) {
            await db.update(appBuilds).set({
              status: "errored",
              errorMessage: err?.message?.slice(0, 1000) || "خطأ غير معروف",
              updatedAt: new Date(),
            }).where(eq(appBuilds.id, build.id));
          }
        })();

        return { buildId: build.id };
      }),

    // ── AI Code Review before build ──────────────────────────────
    reviewCode: protectedProcedure
      .input(z.object({
        code: z.string().min(50),
        errorLog: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { aiReviewAndFix } = await import("./services/eas-builder.js");
        return aiReviewAndFix(input.code, input.errorLog);
      }),

    // ── Generate Advanced App Code (with data, APIs, Supabase) ──────
    generateAdvancedCode: protectedProcedure
      .input(z.object({
        appName: z.string(),
        description: z.string(),
        model: z.enum(["claude", "deepseek"]).default("claude"),
        dataFiles: z.array(z.object({ filename: z.string(), preview: z.string() })).optional(),
        apiEndpoints: z.array(z.string().url()).optional(),
        useSupabase: z.boolean().default(false),
        features: z.array(z.string()).optional(),
      }))
      .mutation(async ({ input }) => {
        let dataContext = "";
        if (input.dataFiles?.length) {
          dataContext = `\n\nبيانات مدمجة مع التطبيق (ملفات JSON في مجلد data/):\n`;
          for (const d of input.dataFiles) {
            dataContext += `- ${d.filename}: ${d.preview.substring(0, 500)}\n`;
          }
          dataContext += `\nلتحميل البيانات استخدم: const data = require('./data/${input.dataFiles[0].filename}');\n`;
        }

        let apiContext = "";
        if (input.apiEndpoints?.length) {
          apiContext = `\n\nAPIs خارجية متاحة:\n${input.apiEndpoints.map(u => `- ${u}`).join("\n")}\nاستخدم fetch() لجلب البيانات مع try/catch و loading state.\n`;
        }

        let supabaseContext = "";
        if (input.useSupabase) {
          supabaseContext = `\n\nSupabase متاح: import { supabase } from './supabase';\nاستخدمه لـ CRUD:\n- القراءة: const { data } = await supabase.from('table').select('*');\n- الإضافة: await supabase.from('table').insert({ ... });\n- التحديث: await supabase.from('table').update({ ... }).eq('id', id);\n- الحذف: await supabase.from('table').delete().eq('id', id);\n`;
        }

        let featuresContext = "";
        if (input.features?.length) {
          const featureMap: Record<string, string> = {
            camera: "الكاميرا: import { CameraView, useCameraPermissions } from 'expo-camera'",
            location: "الموقع: import * as Location from 'expo-location'",
            notifications: "الإشعارات: import * as Notifications from 'expo-notifications'",
            imagePicker: "اختيار صور: import * as ImagePicker from 'expo-image-picker'",
            fileSystem: "نظام الملفات: import * as FileSystem from 'expo-file-system'",
            sharing: "مشاركة: import * as Sharing from 'expo-sharing'",
            sensors: "المستشعرات: import { Accelerometer } from 'expo-sensors'",
            webBrowser: "المتصفح: import * as WebBrowser from 'expo-web-browser'",
          };
          featuresContext = `\n\nميزات مطلوبة:\n${input.features.map(f => featureMap[f] || f).join("\n")}\n`;
        }

        const systemPrompt = `أنت مطور React Native/Expo من المستوى العالمي. مهمتك بناء تطبيق متقدم وكامل.

المطلوب: كود App.tsx واحد — لا شرح، لا markdown.
الحزم المتاحة: react-native core, expo-status-bar, @expo/vector-icons, expo-clipboard, expo-linear-gradient, expo-haptics, expo-blur, @react-native-async-storage/async-storage, expo-file-system, expo-sharing, expo-image-picker, expo-camera, expo-location, expo-notifications, expo-device, expo-sensors, expo-web-browser, expo-linking, fetch() API.
${input.useSupabase ? "@supabase/supabase-js متاح أيضاً." : ""}

خطوط آمنة: sans-serif, serif, monospace فقط.
ممنوع: expo-font, react-navigation, expo-router.
${dataContext}${apiContext}${supabaseContext}${featuresContext}`;

        const userPrompt = `اسم التطبيق: ${input.appName}\nالوصف: ${input.description}\n\nأعد كود App.tsx كامل ومتقدم.`;

        let code = "";
        if (input.model === "deepseek") {
          const key = process.env.DEEPSEEK_API_KEY;
          if (!key) throw new Error("DEEPSEEK_API_KEY غير مضبوط");
          const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
            method: "POST",
            headers: { "Authorization": `Bearer ${key}`, "Content-Type": "application/json" },
            body: JSON.stringify({ model: "deepseek-chat", max_tokens: 12000, temperature: 0.2, messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userPrompt }] }),
          });
          const data = await res.json() as any;
          code = data.choices?.[0]?.message?.content || "";
        } else {
          const { createAnthropicClient } = await import("./llm.js");
          const anthropic = createAnthropicClient();
          const msg = await anthropic.messages.create({ model: "claude-opus-4-5", max_tokens: 12000, system: systemPrompt, messages: [{ role: "user", content: userPrompt }] });
          code = (msg.content[0] as any).text || "";
        }
        code = code.replace(/^```(?:tsx?|javascript|jsx)?\n?/i, "").replace(/\n?```\s*$/i, "").trim();
        if (!code || code.length < 50) throw new Error("فشل التوليد");
        return { code };
      }),

    // ── Generate Desktop App Code (Electron) ─────────────────────
    generateDesktopCode: protectedProcedure
      .input(z.object({
        appName: z.string(),
        description: z.string(),
        model: z.enum(["claude", "deepseek"]).default("claude"),
      }))
      .mutation(async ({ input }) => {
        const systemPrompt = `أنت مطور تطبيقات Desktop باستخدام Electron + HTML + CSS + JavaScript.

القواعد:
1. أعد كود JavaScript كامل لملف app.js واحد يعمل داخل Electron
2. استخدم HTML DOM APIs مباشرة (document.createElement, querySelector, etc.)
3. يمكنك استخدام Node.js APIs (fs, path, os, child_process) لأن Electron يدعمها
4. التصميم يكون جميل واحترافي — ألوان داكنة وحديثة
5. الكود يجب أن يعمل بدون أي مكتبات خارجية
6. أعد الكود مباشرة — بدون شرح أو markdown

الكود يبدأ بتحديد root element ويبني الواجهة فيه:
const root = document.getElementById('root');`;

        const userPrompt = `اسم التطبيق: ${input.appName}\nالوصف: ${input.description}\n\nالمطلوب: كود app.js كامل لتطبيق Electron Desktop.`;

        let code = "";

        if (input.model === "deepseek") {
          const deepseekKey = process.env.DEEPSEEK_API_KEY;
          if (!deepseekKey) throw new Error("DEEPSEEK_API_KEY غير مضبوط");
          const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
            method: "POST",
            headers: { "Authorization": `Bearer ${deepseekKey}`, "Content-Type": "application/json" },
            body: JSON.stringify({
              model: "deepseek-chat", max_tokens: 8192, temperature: 0.2,
              messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userPrompt }],
            }),
          });
          const data = await res.json() as any;
          code = data.choices?.[0]?.message?.content || "";
        } else {
          const { createAnthropicClient } = await import("./llm.js");
          const anthropic = createAnthropicClient();
          const msg = await anthropic.messages.create({
            model: "claude-opus-4-5", max_tokens: 8192,
            system: systemPrompt,
            messages: [{ role: "user", content: userPrompt }],
          });
          code = (msg.content[0] as any).text || "";
        }

        code = code.replace(/^```(?:js|javascript)?\n?/i, "").replace(/\n?```\s*$/i, "").trim();
        if (!code || code.length < 50) throw new Error("النموذج لم يُعِد كوداً كافياً");
        return { code };
      }),

    // ── Build Real Windows EXE (electron-packager) ────────────────
    createDesktop: protectedProcedure
      .input(z.object({
        appName: z.string(),
        description: z.string(),
        generatedCode: z.string(),
        iconBase64: z.string().optional(),
        model: z.enum(["claude", "deepseek"]).default("claude"),
      }))
      .mutation(async ({ input, ctx }) => {
        const { db } = await import("@workspace/db");
        const { appBuilds } = await import("@workspace/db/schema");

        const [build] = await db.insert(appBuilds).values({
          userId: ctx.user.id,
          appName: input.appName,
          description: input.description,
          generatedCode: input.generatedCode,
          status: "pending",
          platform: "windows",
        }).returning();

        // Background build
        (async () => {
          const { eq } = await import("drizzle-orm");
          try {
            await db.update(appBuilds).set({ status: "building", updatedAt: new Date() }).where(eq(appBuilds.id, build.id));
            const { buildWindowsApp } = await import("./services/eas-builder.js");
            const { zipPath, filename } = await buildWindowsApp(input.appName, input.generatedCode, build.id, input.iconBase64);
            const downloadToken = `${build.id}-${crypto.randomBytes(8).toString("hex")}`;
            // Store token → file mapping
            desktopDownloadMap.set(downloadToken, { zipPath, filename, expiresAt: Date.now() + 24 * 60 * 60 * 1000 });
            const downloadUrl = `/api/builds/desktop-download/${downloadToken}`;
            await db.update(appBuilds).set({
              status: "finished",
              downloadUrl,
              updatedAt: new Date(),
            }).where(eq(appBuilds.id, build.id));
          } catch (err: any) {
            const { eq } = await import("drizzle-orm");
            await db.update(appBuilds).set({
              status: "errored",
              errorMessage: err?.message?.slice(0, 1000) || "فشل بناء Windows",
              updatedAt: new Date(),
            }).where(eq(appBuilds.id, build.id));
          }
        })();

        return { buildId: build.id };
      }),

    // ── Generate Desktop Project ZIP ───────────────────────────────
    generateDesktopZip: protectedProcedure
      .input(z.object({
        appName: z.string(),
        code: z.string(),
        iconBase64: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { createElectronZip } = await import("./services/eas-builder.js");
        const buf = await createElectronZip(input.appName, input.code, input.iconBase64);
        return { zipBase64: buf.toString("base64"), filename: `${input.appName || "desktop-app"}-electron.zip` };
      }),

    // ── Package Uploaded Desktop ZIP ──────────────────────────────
    packageDesktopZip: protectedProcedure
      .input(z.object({
        appName: z.string(),
        zipBase64: z.string(),
        iconBase64: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { packageDesktopUpload } = await import("./services/eas-builder.js");
        const buf = await packageDesktopUpload(input.zipBase64, input.appName, input.iconBase64);
        return { zipBase64: buf.toString("base64"), filename: `${input.appName || "desktop-app"}-electron.zip` };
      }),
  }),

  // ==================== Trading Analysis ====================
  tradingAnalysis: router({
    // ── Fetch Economic News (ForexFactory calendar) ─────────────
    economicNews: protectedProcedure.query(async () => {
      try {
        const url = "https://nfs.faireconomy.media/ff_calendar_thisweek.json";
        const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const raw = await res.json() as any[];
        const now = new Date();
        const events = raw
          .filter((e: any) => e.impact === "High" || e.impact === "Medium")
          .map((e: any) => ({
            date: e.date,
            time: e.time,
            currency: e.country,
            title: e.title,
            impact: e.impact,
            forecast: e.forecast || "",
            previous: e.previous || "",
            actual: e.actual || "",
          }))
          .sort((a: any, b: any) => new Date(a.date + " " + a.time).getTime() - new Date(b.date + " " + b.time).getTime());
        const upcoming = events.filter((e: any) => {
          const t = new Date(e.date + " " + e.time.replace("am", " AM").replace("pm", " PM"));
          return t.getTime() >= now.getTime() - 3 * 3600000; // ±3h window
        }).slice(0, 15);
        return { events: upcoming, fetchedAt: now.toISOString(), error: null };
      } catch (e: any) {
        return { events: [], fetchedAt: new Date().toISOString(), error: e.message };
      }
    }),

    // ── Quick Scan: Technical-only, no AI, no credits ─────────────
    quickScan: protectedProcedure
      .input(z.object({
        pairs: z.array(z.enum(["EURUSD", "USDJPY", "GBPUSD", "GBPJPY", "USDCHF", "AUDUSD", "NZDUSD", "USDCAD", "EURGBP", "EURJPY", "EURCHF", "AUDCAD", "XAUUSD", "XAGUSD", "BTCUSD", "ETHUSD", "USOIL", "US30"])).default(["EURUSD", "USDJPY", "GBPUSD", "GBPJPY", "USDCHF", "AUDUSD", "NZDUSD", "USDCAD", "EURGBP", "EURJPY", "EURCHF", "AUDCAD", "XAUUSD", "XAGUSD", "BTCUSD", "ETHUSD", "USOIL", "US30"]),
        timeframe: z.enum(["1min", "5min", "15min", "30min", "1h"]).default("15min"),
      }))
      .mutation(async ({ input }) => {
        const symbolMap: Record<string, string> = {
          EURUSD: "EUR/USD", USDJPY: "USD/JPY", GBPUSD: "GBP/USD",
          GBPJPY: "GBP/JPY", USDCHF: "USD/CHF", AUDUSD: "AUD/USD",
          NZDUSD: "NZD/USD", USDCAD: "USD/CAD",
          EURGBP: "EUR/GBP", EURJPY: "EUR/JPY", EURCHF: "EUR/CHF", AUDCAD: "AUD/CAD",
          XAUUSD: "XAU/USD", XAGUSD: "XAG/USD",
          BTCUSD: "BTC/USD", ETHUSD: "ETH/USD",
          USOIL: "CL", US30: "DJIA",
        };

        const PAIR_FLAGS: Record<string, string> = {
          EURUSD: "🇪🇺🇺🇸", USDJPY: "🇺🇸🇯🇵", GBPUSD: "🇬🇧🇺🇸",
          GBPJPY: "🇬🇧🇯🇵", USDCHF: "🇺🇸🇨🇭", AUDUSD: "🇦🇺🇺🇸",
          NZDUSD: "🇳🇿🇺🇸", USDCAD: "🇺🇸🇨🇦",
          EURGBP: "🇪🇺🇬🇧", EURJPY: "🇪🇺🇯🇵", EURCHF: "🇪🇺🇨🇭", AUDCAD: "🇦🇺🇨🇦",
          XAUUSD: "🥇", XAGUSD: "🥈",
          BTCUSD: "₿", ETHUSD: "⟠",
          USOIL: "🛢️", US30: "🏛️",
        };

        async function scanOnePair(pair: string) {
            const symbol = symbolMap[pair];
            const data = await fetchTwelveData(`https://api.twelvedata.com/time_series?symbol=${encodeURIComponent(symbol)}&interval=${input.timeframe}&outputsize=60&apikey=__API_KEY__`);
            if (data.status === "error" || !data.values || !Array.isArray(data.values)) {
              throw new Error(`${pair}: ${data.message || "فشل"}`);
            }
            const candles = [...data.values].reverse() as any[];
            const closes = candles.map((c: any) => parseFloat(c.close));
            const highs  = candles.map((c: any) => parseFloat(c.high));
            const lows   = candles.map((c: any) => parseFloat(c.low));
            const price  = closes[closes.length - 1];
            const decimals = ["XAUUSD","BTCUSD","ETHUSD","USOIL"].includes(pair) ? 2 : pair === "US30" ? 0 : pair === "XAGUSD" ? 4 : pair.includes("JPY") ? 3 : 5;

            const rsi  = calcRSI(closes);
            const sma20 = calcSMA(closes, 20);
            const sma50 = calcSMA(closes, 50);
            const sma200 = closes.length >= 200 ? calcSMA(closes, 200) : null;
            const macd = calcMACD(closes);
            const bb   = calcBB(closes);
            const atr  = calcATR(highs, lows, closes);

            const strategies = calcStrategies(closes, highs, lows, sma20, sma50, sma200, rsi, macd, bb, atr, undefined, undefined, undefined, undefined);
            const filters    = calcFilters(price, sma20, sma50, sma200, rsi, atr, closes);

            const buySigs  = strategies.filter(s => s.signal === "BUY").length;
            const sellSigs = strategies.filter(s => s.signal === "SELL").length;
            const passedFilters = filters.filter(f => f.passed).length;

            const dominant = buySigs > sellSigs ? "BUY" : sellSigs > buySigs ? "SELL" : "NEUTRAL";
            const dominantCount = Math.max(buySigs, sellSigs);

            const quality = dominantCount >= 3 && passedFilters >= 3 ? "HIGH" :
                            dominantCount >= 2 && passedFilters >= 2 ? "MEDIUM" : "LOW";

            const avgStr = Math.round(strategies
              .filter(s => s.signal === dominant && s.signal !== "NEUTRAL")
              .reduce((a, s) => a + s.strength, 0) / (dominantCount || 1));

            return {
              pair,
              flag: PAIR_FLAGS[pair],
              price: price.toFixed(decimals),
              signal: dominant,
              quality,
              buySigs,
              sellSigs,
              passedFilters,
              totalFilters: filters.length,
              avgStrength: avgStr,
              rsi: rsi.toFixed(1),
              timeframe: input.timeframe,
            };
        }

        const results: PromiseSettledResult<any>[] = [];
        const BATCH_SIZE = 3;
        for (let i = 0; i < input.pairs.length; i += BATCH_SIZE) {
          const batch = input.pairs.slice(i, i + BATCH_SIZE);
          const batchResults = await Promise.allSettled(batch.map(p => scanOnePair(p)));
          results.push(...batchResults);
          if (i + BATCH_SIZE < input.pairs.length) await new Promise(r => setTimeout(r, 1200));
        }

        const signals = results.map((r, i) => {
          if (r.status === "fulfilled") return r.value;
          return {
            pair: input.pairs[i],
            flag: "⚠️",
            price: "0",
            signal: "NEUTRAL" as const,
            quality: "LOW" as const,
            buySigs: 0,
            sellSigs: 0,
            passedFilters: 0,
            totalFilters: 4,
            avgStrength: 0,
            rsi: "0",
            timeframe: input.timeframe,
            error: (r.reason as Error).message,
          };
        });

        const highQuality = signals.filter(s => s.quality === "HIGH" && s.signal !== "NEUTRAL");

        let aiSummary: { provider: string; providerName: string; icon: string; signal: string; confidence: number; reasoning: string }[] | undefined;
        if (highQuality.length > 0) {
          const scanAIProviders: AIProvider[] = ["claude", "geminiPro", "deepseek"];
          const scanSummary = highQuality.map(s =>
            `${s.flag} ${s.pair}: ${s.signal} | السعر: ${s.price} | RSI: ${s.rsi} | قوة: ${s.avgStrength}% | فلاتر: ${s.passedFilters}/${s.totalFilters}`
          ).join("\n");

          const scanPrompt = `أنت محلل أسواق مالية. إليك نتائج مسح سريع للأزواج ذات الجودة العالية:
${scanSummary}

قيّم هذه الإشارات بسرعة. هل توافق عليها؟ أجب بـ JSON فقط:
{"signal":"BUY/SELL/HOLD","confidence":رقم 0-100,"reasoning":"جملة أو جملتين"}`;

          const scanAISettled = await Promise.allSettled(
            scanAIProviders.map(async (provider) => {
              if (!isProviderAvailable(provider)) return null;
              const res = await callProvider(provider, scanPrompt, `مسح سريع — ${highQuality.length} إشارة عالية الجودة`);
              let jsonStr = res.content.trim();
              const fenced = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
              if (fenced) jsonStr = fenced[1].trim();
              const si = jsonStr.indexOf("{"), ei = jsonStr.lastIndexOf("}");
              if (si !== -1 && ei !== -1) jsonStr = jsonStr.slice(si, ei + 1);
              try {
                const p = JSON.parse(jsonStr);
                return {
                  provider, providerName: PROVIDER_CONFIGS[provider].name,
                  icon: PROVIDER_CONFIGS[provider].icon,
                  signal: p.signal || "HOLD", confidence: Number(p.confidence) || 50,
                  reasoning: p.reasoning || "",
                };
              } catch {
                return {
                  provider, providerName: PROVIDER_CONFIGS[provider].name,
                  icon: PROVIDER_CONFIGS[provider].icon,
                  signal: "HOLD", confidence: 50, reasoning: res.content.slice(0, 150),
                };
              }
            })
          );

          aiSummary = scanAISettled
            .filter((r): r is PromiseFulfilledResult<any> => r.status === "fulfilled" && r.value !== null)
            .map(r => r.value);
        }

        return {
          signals,
          scannedAt: new Date().toISOString(),
          timeframe: input.timeframe,
          highQuality,
          aiSummary,
        };
      }),

    // ── Convergence (التطابق) ────────────────────────────────────────
    convergenceStatus: protectedProcedure.query(async () => {
      const { getConvergenceConfig, getConvergenceSignals } = await import("../telegram/bot.js");
      return { config: getConvergenceConfig(), signals: getConvergenceSignals() };
    }),

    convergenceToggle: protectedProcedure
      .input(z.object({ enabled: z.boolean() }))
      .mutation(async ({ input }) => {
        const { setConvergenceConfig, getConvergenceConfig } = await import("../telegram/bot.js");
        setConvergenceConfig({ enabled: input.enabled });
        return { config: getConvergenceConfig() };
      }),

    convergenceSetInterval: protectedProcedure
      .input(z.object({ intervalMinutes: z.number().min(1).max(15) }))
      .mutation(async ({ input }) => {
        const { setConvergenceConfig, getConvergenceConfig } = await import("../telegram/bot.js");
        setConvergenceConfig({ intervalMinutes: input.intervalMinutes });
        return { config: getConvergenceConfig() };
      }),

    convergenceScanNow: protectedProcedure.mutation(async () => {
      const { triggerConvergenceScan, getConvergenceSignals } = await import("../telegram/bot.js");
      const fn = triggerConvergenceScan();
      if (fn) await fn();
      return { signals: getConvergenceSignals() };
    }),

    convergenceTestSignal: protectedProcedure.mutation(async () => {
      const { sendTestConvergenceSignal } = await import("../telegram/bot.js");
      const result = await sendTestConvergenceSignal();
      return { result };
    }),

    // ── Send Full Analysis to Telegram ────────────────────────────────
    sendToTelegram: protectedProcedure
      .input(z.object({
        pair: z.string(),
        timeframe: z.string(),
        price: z.number(),
        signal: z.string(),
        confidence: z.number(),
        indicators: z.object({
          rsi: z.number(),
          macd: z.object({ macd: z.number(), signal: z.number(), histogram: z.number() }),
          sma20: z.number(),
          sma50: z.number(),
          sma200: z.number().nullable(),
          bb: z.object({ upper: z.number(), lower: z.number(), middle: z.number() }),
          atr: z.number(),
          stoch: z.object({ k: z.number(), d: z.number() }).optional(),
          williamsR: z.number().optional(),
          adx: z.object({ adx: z.number(), pdi: z.number(), mdi: z.number() }).optional(),
          pivots: z.object({ pivot: z.number(), r1: z.number(), r2: z.number(), s1: z.number(), s2: z.number() }).optional(),
        }),
        strategySignals: z.array(z.object({
          name: z.string(),
          signal: z.string(),
          strength: z.number(),
          emoji: z.string(),
        })),
        filterResults: z.array(z.object({
          name: z.string(),
          passed: z.boolean(),
          desc: z.string(),
          emoji: z.string(),
        })),
        aiResults: z.array(z.object({
          name: z.string(),
          icon: z.string(),
          signal: z.string(),
          confidence: z.number(),
          reasoning: z.string(),
          entryZone: z.string(),
          stopLoss: z.string(),
          takeProfit: z.string(),
          risk: z.string().optional(),
          available: z.boolean(),
        })),
      }))
      .mutation(async ({ input, ctx }) => {
        const botToken = process.env.TELEGRAM_BOT_TOKEN;
        const chatId = process.env.TELEGRAM_OWNER_CHAT_ID;

        if (!botToken) {
          const { db } = await import("@workspace/db");
          const { telegramBots } = await import("@workspace/db/schema");
          const { eq } = await import("drizzle-orm");
          const bots = await db.select().from(telegramBots)
            .where(eq(telegramBots.userId, ctx.user.id)).limit(1);
          if (!bots[0]?.isActive || !bots[0].botToken) {
            throw new TRPCError({ code: "PRECONDITION_FAILED", message: "لم يتم ضبط بوت Telegram (TELEGRAM_BOT_TOKEN أو إعدادات البوت)" });
          }
        }
        const finalToken = botToken || "";
        if (!chatId) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "TELEGRAM_OWNER_CHAT_ID غير مضبوط" });
        }

        const flagMap: Record<string, string> = {
          EURUSD: "🇪🇺🇺🇸", USDJPY: "🇺🇸🇯🇵", GBPUSD: "🇬🇧🇺🇸",
          GBPJPY: "🇬🇧🇯🇵", XAUUSD: "🥇🇺🇸",
          BTCUSD: "₿", USDCHF: "🇺🇸🇨🇭", AUDUSD: "🇦🇺🇺🇸", XAGUSD: "🥈",
        };
        const tfMap: Record<string, string> = {
          "1min": "1m", "5min": "5m", "15min": "15m", "30min": "30m", "1h": "1h",
        };

        const flag = flagMap[input.pair] || "📊";
        const pairLabel = input.pair.replace(/(.{3})(.{3,})/, "$1/$2");
        const tfLabel = tfMap[input.timeframe] ?? input.timeframe;
        const utcTime = new Date().toISOString().slice(11, 16) + " UTC";
        const decimals = input.pair === "BTCUSD" ? 1 : input.pair === "XAUUSD" ? 2 : input.pair === "XAGUSD" ? 3 : input.pair.includes("JPY") ? 3 : 5;
        const fmt = (n: number) => n.toFixed(decimals);
        const ind = input.indicators;
        const macdDir = ind.macd.macd > ind.macd.signal ? "✅ صاعد" : "❌ هابط";
        const rsiLabel = ind.rsi > 70 ? "🔴 ذروة شراء" : ind.rsi < 30 ? "🟢 ذروة بيع" : "⚪";
        const priceAboveSMA20 = input.price > ind.sma20;
        const priceAboveSMA50 = input.price > ind.sma50;
        const bbPos = input.price > ind.bb.upper ? "↑ فوق العلوي" : input.price < ind.bb.lower ? "↓ تحت السفلي" : "↔ داخل النطاق";

        const buySigs = input.strategySignals.filter(s => s.signal === "BUY").length;
        const sellSigs = input.strategySignals.filter(s => s.signal === "SELL").length;
        const neutralSigs = input.strategySignals.length - buySigs - sellSigs;

        const lines: string[] = [];
        lines.push(`${flag} تحليل AI كامل — ${pairLabel} | ${tfLabel}`);
        lines.push(`💰 ${fmt(input.price)}  ${utcTime}`);
        lines.push(`━━ 📊 المؤشرات ━━`);
        lines.push(`RSI ${ind.rsi.toFixed(1)} ${rsiLabel} | MACD ${macdDir}`);
        lines.push(`SMA20 ${priceAboveSMA20 ? "✅" : "❌"} | SMA50 ${priceAboveSMA50 ? "✅" : "❌"}`);
        lines.push(`BB ${bbPos} | ATR ${fmt(ind.atr)}`);

        if (ind.stoch) lines.push(`Stoch %K=${ind.stoch.k.toFixed(0)} %D=${ind.stoch.d.toFixed(0)} ${ind.stoch.k > 80 ? "⚠️ ذروة شراء" : ind.stoch.k < 20 ? "⚠️ ذروة بيع" : ""}`);
        if (ind.adx) lines.push(`ADX ${ind.adx.adx.toFixed(1)} ${ind.adx.adx > 25 ? "📈 اتجاه قوي" : "➡️ جانبي"} | +DI ${ind.adx.pdi.toFixed(1)} -DI ${ind.adx.mdi.toFixed(1)}`);
        if (ind.pivots) lines.push(`Pivot ${fmt(ind.pivots.pivot)} | R1 ${fmt(ind.pivots.r1)} R2 ${fmt(ind.pivots.r2)} | S1 ${fmt(ind.pivots.s1)} S2 ${fmt(ind.pivots.s2)}`);

        lines.push(`━━ 🎯 الاستراتيجيات (${buySigs}🟢 ${sellSigs}🔴 ${neutralSigs}🟡) ━━`);
        for (const s of input.strategySignals) {
          const sigIcon = s.signal === "BUY" ? "🟢 شراء" : s.signal === "SELL" ? "🔴 بيع" : "🟡 محايد";
          lines.push(`${s.emoji} ${s.name}: ${sigIcon}${s.strength > 0 ? ` ${s.strength}%` : ""}`);
        }

        lines.push(`━━ 🔍 الفلاتر ━━`);
        for (const f of input.filterResults) {
          lines.push(`${f.passed ? "✅" : "⚠️"} ${f.emoji} ${f.name}: ${f.desc}`);
        }

        const availableAI = input.aiResults.filter(r => r.available);
        lines.push(`━━ 🤖 الذكاء الاصطناعي (${availableAI.length} نماذج) ━━`);
        for (const r of input.aiResults) {
          if (!r.available) {
            lines.push(`${r.icon} ${r.name}: ⚠️ غير متاح`);
          } else {
            const sigEmoji = r.signal === "BUY" ? "🟢 شراء" : r.signal === "SELL" ? "🔴 بيع" : "🟡 انتظار";
            const riskLabel = r.risk === "HIGH" ? "🔴 عالي" : r.risk === "MEDIUM" ? "🟡 متوسط" : "🟢 منخفض";
            lines.push(`${r.icon} ${r.name}: ${sigEmoji} ${r.confidence}% | خطر: ${riskLabel}`);
            if (r.reasoning) {
              lines.push(`   💬 ${r.reasoning.slice(0, 200)}${r.reasoning.length > 200 ? "…" : ""}`);
            }
            lines.push(`   🎯 دخول ${r.entryZone} | SL ${r.stopLoss} | TP ${r.takeProfit}`);
          }
        }

        const signalEmoji = input.signal === "BUY" ? "🟢 شراء" : input.signal === "SELL" ? "🔴 بيع" : "🟡 انتظار";
        lines.push(`┌────────────────────────────────┐`);
        lines.push(`│  AI توافق: ${signalEmoji}  ثقة: ${input.confidence}%  │`);
        lines.push(`└────────────────────────────────┘`);
        lines.push(`⚠️ للأغراض التعليمية فقط — ليس توصية مالية`);

        const text = lines.join("\n");

        const sendRes = await fetch(`https://api.telegram.org/bot${finalToken}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: chatId, text }),
          signal: AbortSignal.timeout(10000),
        });

        if (!sendRes.ok) {
          const err = await sendRes.json() as any;
          throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `فشل الإرسال: ${err?.description || sendRes.statusText}` });
        }

        return { success: true, chatId };
      }),

    // ── Auto Signal: Multi-Timeframe Cross Detection + Telegram Alert ──
    autoSignal: protectedProcedure
      .input(z.object({
        pairs: z.array(z.enum(["EURUSD", "USDJPY", "GBPUSD", "GBPJPY", "USDCHF", "AUDUSD", "NZDUSD", "USDCAD", "EURGBP", "EURJPY", "EURCHF", "AUDCAD", "XAUUSD", "XAGUSD", "BTCUSD", "ETHUSD", "USOIL", "US30"]))
          .default(["EURUSD", "USDJPY", "GBPUSD", "GBPJPY", "USDCHF", "AUDUSD", "NZDUSD", "USDCAD", "EURGBP", "EURJPY", "EURCHF", "AUDCAD", "XAUUSD", "XAGUSD", "BTCUSD", "ETHUSD", "USOIL", "US30"]),
        sendToTelegram: z.boolean().default(true),
        minStrategies: z.number().min(2).max(10).default(4),
        minFilters: z.number().min(1).max(5).default(3),
      }))
      .mutation(async ({ input, ctx }) => {
        const symbolMap: Record<string, string> = {
          EURUSD: "EUR/USD", USDJPY: "USD/JPY", GBPUSD: "GBP/USD",
          GBPJPY: "GBP/JPY", USDCHF: "USD/CHF", AUDUSD: "AUD/USD",
          NZDUSD: "NZD/USD", USDCAD: "USD/CAD",
          EURGBP: "EUR/GBP", EURJPY: "EUR/JPY", EURCHF: "EUR/CHF", AUDCAD: "AUD/CAD",
          XAUUSD: "XAU/USD", XAGUSD: "XAG/USD",
          BTCUSD: "BTC/USD", ETHUSD: "ETH/USD",
          USOIL: "CL", US30: "DJIA",
        };
        const PAIR_FLAGS: Record<string, string> = {
          EURUSD: "🇪🇺🇺🇸", USDJPY: "🇺🇸🇯🇵", GBPUSD: "🇬🇧🇺🇸",
          GBPJPY: "🇬🇧🇯🇵", USDCHF: "🇺🇸🇨🇭", AUDUSD: "🇦🇺🇺🇸",
          NZDUSD: "🇳🇿🇺🇸", USDCAD: "🇺🇸🇨🇦",
          EURGBP: "🇪🇺🇬🇧", EURJPY: "🇪🇺🇯🇵", EURCHF: "🇪🇺🇨🇭", AUDCAD: "🇦🇺🇨🇦",
          XAUUSD: "🥇", XAGUSD: "🥈",
          BTCUSD: "₿", ETHUSD: "⟠",
          USOIL: "🛢️", US30: "🏛️",
        };

        const timeframes = ["1min", "5min", "15min"] as const;
        const confirmedSignals: Array<{
          pair: string; flag: string; signal: "BUY" | "SELL";
          confidence: number; price: string;
          tf1: { signal: string; buys: number; sells: number; strength: number };
          tf5: { signal: string; buys: number; sells: number; strength: number };
          tf15: { signal: string; buys: number; sells: number; strength: number };
          strategies: string[];
          filters: { passed: number; total: number };
          indicators: { rsi: number; stochK: number; adx: number; macd: string };
          entryZone: string; stopLoss: string; takeProfit: string;
        }> = [];

        // Analyze each pair across 3 timeframes
        for (const pair of input.pairs) {
          const symbol = symbolMap[pair];
          const tfResults: Record<string, {
            signal: "BUY" | "SELL" | "NEUTRAL"; buys: number; sells: number;
            avgStrength: number; passedFilters: number; totalFilters: number;
            price: number; rsi: number; stochK: number; adx: number; macdDir: string;
            strategies: StrategySignal[]; atr: number;
          }> = {};

          let latestPrice = 0;
          let lastATR = 0;

          for (const tf of timeframes) {
            try {
              const url = `https://api.twelvedata.com/time_series?symbol=${encodeURIComponent(symbol)}&interval=${tf}&outputsize=100&apikey=__API_KEY__`;
              const res = await fetch(url, { signal: AbortSignal.timeout(12000) });
              const data = await res.json() as any;
              if (data.status === "error" || !data.values) continue;

              const candles = [...data.values].reverse() as any[];
              const closes = candles.map((c: any) => parseFloat(c.close));
              const highs = candles.map((c: any) => parseFloat(c.high));
              const lows = candles.map((c: any) => parseFloat(c.low));
              const price = closes[closes.length - 1];
              if (tf === "15min") latestPrice = price;

              const rsi = calcRSI(closes);
              const sma20 = calcSMA(closes, 20);
              const sma50 = calcSMA(closes, 50);
              const sma200 = closes.length >= 200 ? calcSMA(closes, 200) : null;
              const macd = calcMACD(closes);
              const bb = calcBB(closes);
              const atr = calcATR(highs, lows, closes);
              const stoch = calcStochastic(closes, highs, lows);
              const williamsR = calcWilliamsR(closes, highs, lows);
              const adxVal = calcADX(highs, lows, closes);
              const pivots = calcPivotPoints(highs, lows, closes);
              lastATR = atr;

              const strategies = calcStrategies(closes, highs, lows, sma20, sma50, sma200, rsi, macd, bb, atr, stoch, williamsR, adxVal, pivots);
              const filters = calcFilters(price, sma20, sma50, sma200, rsi, atr, closes);

              const buys = strategies.filter(s => s.signal === "BUY").length;
              const sells = strategies.filter(s => s.signal === "SELL").length;
              const dominant = buys > sells ? "BUY" as const : sells > buys ? "SELL" as const : "NEUTRAL" as const;
              const nonNeutral = strategies.filter(s => s.signal !== "NEUTRAL");
              const avgStr = nonNeutral.length ? Math.round(nonNeutral.reduce((a, s) => a + s.strength, 0) / nonNeutral.length) : 0;

              tfResults[tf] = {
                signal: dominant, buys, sells, avgStrength: avgStr,
                passedFilters: filters.filter(f => f.passed).length,
                totalFilters: filters.length,
                price, rsi, stochK: stoch.k, adx: adxVal.adx,
                macdDir: macd.macd > macd.signal ? "صاعد" : "هابط",
                strategies, atr,
              };
            } catch { /* skip failed timeframe */ }
          }

          // Check if all 3 timeframes agree on the same direction
          const tf1 = tfResults["1min"];
          const tf5 = tfResults["5min"];
          const tf15 = tfResults["15min"];

          if (!tf1 || !tf5 || !tf15) continue;
          if (tf1.signal === "NEUTRAL" || tf5.signal === "NEUTRAL" || tf15.signal === "NEUTRAL") continue;

          // All 3 must agree
          if (tf1.signal !== tf5.signal || tf5.signal !== tf15.signal) continue;

          const agreementSignal = tf1.signal;

          // Check minimum strategies threshold across all timeframes
          const totalBuys = tf1.buys + tf5.buys + tf15.buys;
          const totalSells = tf1.sells + tf5.sells + tf15.sells;
          const dominantCount = agreementSignal === "BUY" ? totalBuys : totalSells;
          if (dominantCount < input.minStrategies * 3) continue; // minStrategies per TF

          // Check minimum filters
          const totalPassedFilters = tf1.passedFilters + tf5.passedFilters + tf15.passedFilters;
          if (totalPassedFilters < input.minFilters * 3) continue;

          // Calculate confidence
          const avgStrength = Math.round((tf1.avgStrength + tf5.avgStrength + tf15.avgStrength) / 3);
          const confidence = Math.min(95, avgStrength + Math.round(dominantCount * 2));

          const decimals = pair === "BTCUSD" ? 1 : pair === "XAUUSD" ? 2 : pair === "XAGUSD" ? 3 : pair.includes("JPY") ? 3 : 5;
          const priceFmt = latestPrice.toFixed(decimals);

          // Build top strategies list
          const allStrategies = [...tf15.strategies].filter(s => s.signal === agreementSignal);
          const topStrategies = allStrategies
            .sort((a, b) => b.strength - a.strength)
            .slice(0, 5)
            .map(s => `${s.emoji} ${s.name} (${s.strength}%)`);

          // Calculate SL/TP based on ATR
          const slDistance = lastATR * 1.5;
          const tpDistance = lastATR * 2.5;
          const entryZone = priceFmt;
          const stopLoss = agreementSignal === "BUY"
            ? (latestPrice - slDistance).toFixed(decimals)
            : (latestPrice + slDistance).toFixed(decimals);
          const takeProfit = agreementSignal === "BUY"
            ? (latestPrice + tpDistance).toFixed(decimals)
            : (latestPrice - tpDistance).toFixed(decimals);

          confirmedSignals.push({
            pair, flag: PAIR_FLAGS[pair] || "📊",
            signal: agreementSignal,
            confidence,
            price: priceFmt,
            tf1: { signal: tf1.signal, buys: tf1.buys, sells: tf1.sells, strength: tf1.avgStrength },
            tf5: { signal: tf5.signal, buys: tf5.buys, sells: tf5.sells, strength: tf5.avgStrength },
            tf15: { signal: tf15.signal, buys: tf15.buys, sells: tf15.sells, strength: tf15.avgStrength },
            strategies: topStrategies,
            filters: { passed: totalPassedFilters, total: tf1.totalFilters + tf5.totalFilters + tf15.totalFilters },
            indicators: { rsi: tf15.rsi, stochK: tf15.stochK, adx: tf15.adx, macd: tf15.macdDir },
            entryZone, stopLoss, takeProfit,
          });
        }

        // ── AI Confirmation for each confirmed signal ──
        const aiProviders: AIProvider[] = ["claude", "geminiPro", "deepseek"];
        const aiConfirmedSignals: Array<typeof confirmedSignals[0] & {
          aiAnalysis: Array<{
            provider: string; providerName: string; icon: string; color: string;
            signal: string; confidence: number; reasoning: string;
            entryZone: string; stopLoss: string; takeProfit: string;
            risk: string; available: boolean; duration: number;
          }>;
          aiConsensus: { signal: string; avgConfidence: number; agreementCount: number };
        }> = [];

        for (const sig of confirmedSignals) {
          const aiSystemPrompt = `أنت محلل أسواق مالية خبير. لديك إشارة ${sig.signal === "BUY" ? "شراء" : "بيع"} مؤكدة عبر 3 فريمات زمنية (1M/5M/15M) لزوج ${sig.pair}.
المؤشرات: RSI=${sig.indicators.rsi.toFixed(1)} | Stochastic=%K${sig.indicators.stochK.toFixed(0)} | ADX=${sig.indicators.adx.toFixed(1)} | MACD=${sig.indicators.macd}
الاستراتيجيات: ${sig.strategies.join(" | ")}
الفلاتر: ${sig.filters.passed}/${sig.filters.total} اجتازت
الثقة الحسابية: ${sig.confidence}%

مهمتك: تقييم هذه الإشارة وتأكيدها أو رفضها. هل تتوافق المؤشرات فعلاً؟ هل هناك مخاطر مخفية؟

أجب فقط بـ JSON:
{"signal":"BUY" أو "SELL" أو "HOLD","confidence":رقم 0-100,"reasoning":"تحليل 2-3 جمل","entryZone":"${sig.entryZone}","stopLoss":"وقف","takeProfit":"هدف","risk":"LOW/MEDIUM/HIGH"}`;

          const aiSettled = await Promise.allSettled(
            aiProviders.map(async (provider) => {
              if (!isProviderAvailable(provider)) {
                return {
                  provider, providerName: PROVIDER_CONFIGS[provider].name,
                  icon: PROVIDER_CONFIGS[provider].icon, color: PROVIDER_CONFIGS[provider].color,
                  signal: "HOLD", confidence: 0, reasoning: "المزود غير متاح",
                  entryZone: "-", stopLoss: "-", takeProfit: "-",
                  risk: "LOW", available: false, duration: 0,
                };
              }
              const start = Date.now();
              const res = await callProvider(provider, aiSystemPrompt, `تحليل ${sig.pair} — السعر: ${sig.price}`);
              const duration = Date.now() - start;
              let jsonStr = res.content.trim();
              const fenced = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
              if (fenced) jsonStr = fenced[1].trim();
              const si = jsonStr.indexOf("{"), ei = jsonStr.lastIndexOf("}");
              if (si !== -1 && ei !== -1) jsonStr = jsonStr.slice(si, ei + 1);
              try {
                const p = JSON.parse(jsonStr);
                return {
                  provider, providerName: PROVIDER_CONFIGS[provider].name,
                  icon: PROVIDER_CONFIGS[provider].icon, color: PROVIDER_CONFIGS[provider].color,
                  signal: (["BUY","SELL","HOLD"].includes(p.signal) ? p.signal : "HOLD"),
                  confidence: Math.min(100, Math.max(0, Number(p.confidence) || 50)),
                  reasoning: p.reasoning || "", entryZone: p.entryZone || sig.entryZone,
                  stopLoss: p.stopLoss || sig.stopLoss, takeProfit: p.takeProfit || sig.takeProfit,
                  risk: p.risk || "MEDIUM", available: true, duration,
                };
              } catch {
                return {
                  provider, providerName: PROVIDER_CONFIGS[provider].name,
                  icon: PROVIDER_CONFIGS[provider].icon, color: PROVIDER_CONFIGS[provider].color,
                  signal: "HOLD", confidence: 50, reasoning: res.content.slice(0, 200),
                  entryZone: sig.entryZone, stopLoss: sig.stopLoss, takeProfit: sig.takeProfit,
                  risk: "MEDIUM", available: true, duration,
                };
              }
            })
          );

          const aiResults = aiSettled.map((r, i) => {
            if (r.status === "fulfilled") return r.value;
            return {
              provider: aiProviders[i], providerName: PROVIDER_CONFIGS[aiProviders[i]].name,
              icon: PROVIDER_CONFIGS[aiProviders[i]].icon, color: PROVIDER_CONFIGS[aiProviders[i]].color,
              signal: "HOLD", confidence: 0, reasoning: (r.reason as Error).message,
              entryZone: "-", stopLoss: "-", takeProfit: "-",
              risk: "LOW", available: false, duration: 0,
            };
          });

          const availableAI = aiResults.filter(r => r.available);
          const agreementCount = availableAI.filter(r => r.signal === sig.signal).length;
          const avgConfidence = availableAI.length > 0
            ? Math.round(availableAI.reduce((a, r) => a + r.confidence, 0) / availableAI.length) : 0;
          const aiConsensusSignal = agreementCount >= 2 ? sig.signal : "HOLD";

          aiConfirmedSignals.push({
            ...sig,
            aiAnalysis: aiResults,
            aiConsensus: { signal: aiConsensusSignal, avgConfidence, agreementCount },
          });
        }

        // Send confirmed signals to Telegram (with AI analysis)
        if (input.sendToTelegram && aiConfirmedSignals.length > 0) {
          const botToken = process.env.TELEGRAM_BOT_TOKEN;
          const chatId = process.env.TELEGRAM_OWNER_CHAT_ID;

          if (botToken && chatId) {
            for (const sig of aiConfirmedSignals) {
              const sigEmoji = sig.signal === "BUY" ? "🟢" : "🔴";
              const sigLabel = sig.signal === "BUY" ? "شراء" : "بيع";
              const pairLabel = sig.pair.replace(/(.{3})(.{3,})/, "$1/$2");
              const now = new Date();
              const utcTime = now.toISOString().slice(11, 16) + " UTC";

              const aiLines: string[] = [];
              for (const ai of sig.aiAnalysis) {
                if (!ai.available) {
                  aiLines.push(`  ${ai.icon} ${ai.providerName}: ⚠️ غير متاح`);
                } else {
                  const aiSigEmoji = ai.signal === "BUY" ? "🟢" : ai.signal === "SELL" ? "🔴" : "🟡";
                  aiLines.push(`  ${ai.icon} ${ai.providerName}: ${aiSigEmoji} ${ai.signal} (${ai.confidence}%)`);
                  if (ai.reasoning) aiLines.push(`     💬 ${ai.reasoning.slice(0, 120)}`);
                }
              }

              const consensusEmoji = sig.aiConsensus.signal === sig.signal ? "✅" : "⚠️";

              const msg = [
                `🚨 <b>إشارة تلقائية — Multi-TF + AI Confirmed</b>`,
                ``,
                `${sig.flag} <b>${pairLabel}</b> | ${sigEmoji} <b>${sigLabel.toUpperCase()}</b>`,
                `💰 السعر: <code>${sig.price}</code>  ⏱ ${utcTime}`,
                `━━━━━━━━━━━━━━━━━━━━`,
                `📊 <b>تأكيد 3 فريمات:</b>`,
                `  ⚡ 1M: ${sig.tf1.signal === "BUY" ? "🟢" : "🔴"} ${sig.tf1.buys}↑ ${sig.tf1.sells}↓ (${sig.tf1.strength}%)`,
                `  🕐 5M: ${sig.tf5.signal === "BUY" ? "🟢" : "🔴"} ${sig.tf5.buys}↑ ${sig.tf5.sells}↓ (${sig.tf5.strength}%)`,
                `  🕒 15M: ${sig.tf15.signal === "BUY" ? "🟢" : "🔴"} ${sig.tf15.buys}↑ ${sig.tf15.sells}↓ (${sig.tf15.strength}%)`,
                `━━━━━━━━━━━━━━━━━━━━`,
                `🤖 <b>تحليل الذكاء الاصطناعي (3 نماذج):</b>`,
                ...aiLines,
                `━━━━━━━━━━━━━━━━━━━━`,
                `${consensusEmoji} <b>إجماع AI:</b> ${sig.aiConsensus.signal} | ثقة: ${sig.aiConsensus.avgConfidence}% | توافق: ${sig.aiConsensus.agreementCount}/3`,
                `━━━━━━━━━━━━━━━━━━━━`,
                `📈 <b>المؤشرات (15M):</b>`,
                `  RSI: ${sig.indicators.rsi.toFixed(1)} | Stoch: ${sig.indicators.stochK.toFixed(0)}`,
                `  ADX: ${sig.indicators.adx.toFixed(1)} | MACD: ${sig.indicators.macd}`,
                `━━━━━━━━━━━━━━━━━━━━`,
                `🎯 <b>أقوى الاستراتيجيات:</b>`,
                ...sig.strategies.map(s => `  ${s}`),
                `━━━━━━━━━━━━━━━━━━━━`,
                `✅ فلاتر: ${sig.filters.passed}/${sig.filters.total} اجتازت`,
                `🔥 الثقة: <b>${sig.confidence}%</b>`,
                `━━━━━━━━━━━━━━━━━━━━`,
                `🎯 دخول: <code>${sig.entryZone}</code>`,
                `🛑 وقف: <code>${sig.stopLoss}</code>`,
                `✅ هدف: <code>${sig.takeProfit}</code>`,
                `━━━━━━━━━━━━━━━━━━━━`,
                `⚠️ للأغراض التعليمية فقط — ليست نصيحة مالية`,
              ].join("\n");

              try {
                await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ chat_id: chatId, text: msg, parse_mode: "HTML" }),
                  signal: AbortSignal.timeout(10000),
                });
              } catch (e: any) {
                console.warn(`[AutoSignal] Failed to send to Telegram: ${e.message}`);
              }
            }
          }
        }

        return {
          confirmedSignals: aiConfirmedSignals,
          totalPairsScanned: input.pairs.length,
          signalsFound: aiConfirmedSignals.length,
          scannedAt: new Date().toISOString(),
          config: { minStrategies: input.minStrategies, minFilters: input.minFilters },
        };
      }),

    analyzeMarket: protectedProcedure
      .input(z.object({
        pair: z.enum(["EURUSD", "USDJPY", "GBPUSD", "GBPJPY", "USDCHF", "AUDUSD", "NZDUSD", "USDCAD", "EURGBP", "EURJPY", "EURCHF", "AUDCAD", "XAUUSD", "XAGUSD", "BTCUSD", "ETHUSD", "USOIL", "US30"]),
        timeframe: z.enum(["1min", "5min", "15min", "30min", "1h"]),
      }))
      .mutation(async ({ input, ctx }) => {
        const creditCheck = await checkCredits(ctx.user.id, "war_room");
        if (!creditCheck.allowed) {
          throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: creditCheck.message || "نفدت نقاطك اليومية" });
        }
        await deductCredits(ctx.user.id, "war_room");

        // Map pair to TwelveData symbol
        const symbolMap: Record<string, string> = {
          EURUSD: "EUR/USD", USDJPY: "USD/JPY", GBPUSD: "GBP/USD",
          GBPJPY: "GBP/JPY", USDCHF: "USD/CHF", AUDUSD: "AUD/USD",
          NZDUSD: "NZD/USD", USDCAD: "USD/CAD",
          EURGBP: "EUR/GBP", EURJPY: "EUR/JPY", EURCHF: "EUR/CHF", AUDCAD: "AUD/CAD",
          XAUUSD: "XAU/USD", XAGUSD: "XAG/USD",
          BTCUSD: "BTC/USD", ETHUSD: "ETH/USD",
          USOIL: "CL", US30: "DJIA",
        };

        // Relevant currencies for each pair
        const pairCurrencies: Record<string, string[]> = {
          EURUSD: ["EUR", "USD"], USDJPY: ["USD", "JPY"], GBPUSD: ["GBP", "USD"],
          GBPJPY: ["GBP", "JPY"], XAUUSD: ["USD", "XAU"],
          BTCUSD: ["BTC", "USD"], USDCHF: ["USD", "CHF"], AUDUSD: ["AUD", "USD"], XAGUSD: ["XAG", "USD"],
        };

        const symbol = symbolMap[input.pair];
        const relatedCurrencies = pairCurrencies[input.pair] || ["USD"];

        // Fetch OHLCV + Economic News in parallel
        const [tdRes, newsRes] = await Promise.allSettled([
          fetchTwelveData(`https://api.twelvedata.com/time_series?symbol=${encodeURIComponent(symbol)}&interval=${input.timeframe}&outputsize=100&apikey=__API_KEY__`),
          fetch("https://nfs.faireconomy.media/ff_calendar_thisweek.json",
            { signal: AbortSignal.timeout(8000) }).then(r => r.json()).catch(() => []),
        ]);

        if (tdRes.status === "rejected") {
          throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `فشل الاتصال بـ TwelveData: ${tdRes.reason?.message}` });
        }

        const tdData = tdRes.value as any;
        if (tdData.status === "error" || !tdData.values || !Array.isArray(tdData.values)) {
          throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: tdData.message || "فشل جلب بيانات السوق من TwelveData" });
        }

        // Extract economic news for relevant currencies
        let newsContext = "";
        let economicNewsItems: any[] = [];
        if (newsRes.status === "fulfilled" && Array.isArray(newsRes.value)) {
          const now = new Date();
          const relevantNews = (newsRes.value as any[])
            .filter((e: any) =>
              (e.impact === "High" || e.impact === "Medium") &&
              relatedCurrencies.includes(e.country)
            )
            .map((e: any) => ({
              date: e.date, time: e.time,
              currency: e.country,
              title: e.title,
              impact: e.impact,
              forecast: e.forecast || "—",
              previous: e.previous || "—",
              actual: e.actual || "لم يُعلن",
            }))
            .sort((a: any, b: any) =>
              new Date(a.date).getTime() - new Date(b.date).getTime()
            )
            .slice(0, 10);

          economicNewsItems = relevantNews;

          if (relevantNews.length > 0) {
            newsContext = `\n\n📰 الأخبار الاقتصادية هذا الأسبوع (${relatedCurrencies.join("/")} — تأثير عالي/متوسط):\n` +
              relevantNews.map((e: any) =>
                `• ${e.impact === "High" ? "🔴" : "🟡"} ${e.currency} | ${e.title} | التوقعات: ${e.forecast} | السابق: ${e.previous} | الفعلي: ${e.actual}`
              ).join("\n") +
              "\n⚠️ مهم: راعِ هذه الأخبار عند تحديد مستوى المخاطرة والتوقيت.";
          }
        }

        // Parse candles (TwelveData returns newest first, reverse to oldest-first)
        const candles = [...tdData.values].reverse() as Array<{ open: string; high: string; low: string; close: string; datetime: string }>;
        const closes  = candles.map(c => parseFloat(c.close));
        const highs   = candles.map(c => parseFloat(c.high));
        const lows    = candles.map(c => parseFloat(c.low));
        const currentPrice = closes[closes.length - 1];
        const decimals = input.pair === "BTCUSD" ? 1 : input.pair === "XAUUSD" ? 2 : input.pair === "XAGUSD" ? 3 : input.pair.includes("JPY") ? 3 : 5;
        const fmt = (n: number) => n.toFixed(decimals);

        // Calculate indicators
        const rsi   = calcRSI(closes);
        const sma20 = calcSMA(closes, 20);
        const sma50 = calcSMA(closes, 50);
        const sma200 = closes.length >= 200 ? calcSMA(closes, 200) : null;
        const macd  = calcMACD(closes);
        const bb    = calcBB(closes);
        const atr   = calcATR(highs, lows, closes);
        const stoch = calcStochastic(closes, highs, lows);
        const williamsR = calcWilliamsR(closes, highs, lows);
        const pivots = calcPivotPoints(highs, lows, closes);
        const adx   = calcADX(highs, lows, closes);

        // Calculate strategies and filters
        const strategySignals = calcStrategies(closes, highs, lows, sma20, sma50, sma200, rsi, macd, bb, atr, stoch, williamsR, adx, pivots);
        const filterResults   = calcFilters(currentPrice, sma20, sma50, sma200, rsi, atr, closes);

        // Strategy consensus
        const buySigs  = strategySignals.filter(s => s.signal === "BUY").length;
        const sellSigs = strategySignals.filter(s => s.signal === "SELL").length;
        const avgStrength = strategySignals.filter(s => s.signal !== "NEUTRAL").reduce((a, s) => a + s.strength, 0) / (strategySignals.filter(s => s.signal !== "NEUTRAL").length || 1);
        const passedFilters = filterResults.filter(f => f.passed);
        const trendFilter   = filterResults.find(f => f.id === "trend_filter");
        const sessionFilter = filterResults.find(f => f.id === "session_filter");
        const volFilter     = filterResults.find(f => f.id === "volatility_filter");

        const rsiLabel = rsi > 70 ? "ذروة شراء ⚠️" : rsi < 30 ? "ذروة بيع ⚠️" : "محايد";
        const last5 = candles.slice(-5).map((c, i) => `  ${i + 1}. O:${c.open} H:${c.high} L:${c.low} C:${c.close}`).join("\n");

        const marketContext = `═══════════════════════════════
تحليل زوج ${input.pair} — الإطار الزمني: ${input.timeframe}
السعر الحالي: ${fmt(currentPrice)}
═══════════════════════════════

📊 المؤشرات التقنية:
• RSI(14): ${rsi.toFixed(1)} (${rsiLabel})
• MACD: ${macd.macd.toFixed(5)} | Signal: ${macd.signal.toFixed(5)} | Histogram: ${macd.histogram.toFixed(5)}
• SMA20: ${fmt(sma20)} — السعر ${currentPrice > sma20 ? "فوق ✅" : "تحت ❌"}
• SMA50: ${fmt(sma50)} — السعر ${currentPrice > sma50 ? "فوق ✅" : "تحت ❌"}
${sma200 ? `• SMA200: ${fmt(sma200)} — السعر ${currentPrice > sma200 ? "فوق ✅" : "تحت ❌"}` : "• SMA200: بيانات غير كافية (أقل من 200 شمعة)"}
• BB: Upper ${fmt(bb.upper)} | Mid ${fmt(bb.middle)} | Lower ${fmt(bb.lower)}
• ATR(14): ${fmt(atr)}
• Stochastic: %K=${stoch.k.toFixed(1)} %D=${stoch.d.toFixed(1)} ${stoch.k > 80 ? "⚠️ ذروة شراء" : stoch.k < 20 ? "⚠️ ذروة بيع" : "محايد"}
• Williams %R: ${williamsR.toFixed(1)} ${williamsR > -20 ? "⚠️ ذروة شراء" : williamsR < -80 ? "⚠️ ذروة بيع" : "محايد"}
• ADX: ${adx.adx.toFixed(1)} (+DI: ${adx.pdi.toFixed(1)}, -DI: ${adx.mdi.toFixed(1)}) ${adx.adx > 25 ? "📈 اتجاه قوي" : "➡️ سوق جانبي"}
• Pivot: P=${fmt(pivots.pivot)} | R1=${fmt(pivots.r1)} R2=${fmt(pivots.r2)} | S1=${fmt(pivots.s1)} S2=${fmt(pivots.s2)}

🎯 إشارات الاستراتيجيات (${buySigs} شراء / ${sellSigs} بيع / ${strategySignals.length - buySigs - sellSigs} محايد):
${strategySignals.map(s => `• ${s.emoji} ${s.name}: ${s.signal === "BUY" ? "🟢 BUY" : s.signal === "SELL" ? "🔴 SELL" : "🟡 NEUTRAL"} (قوة: ${s.strength}%) — ${s.desc}`).join("\n")}
متوسط قوة الإشارة: ${avgStrength.toFixed(0)}%

🔍 الفلاتر (${passedFilters.length}/${filterResults.length} اجتازت):
${filterResults.map(f => `• ${f.emoji} ${f.name}: ${f.passed ? "✅" : "⚠️"} — ${f.desc}`).join("\n")}
${!sessionFilter?.passed ? "⚠️ تحذير: خارج الجلسات الرئيسية — دقة الإشارات أقل" : ""}
${!volFilter?.passed ? "⚠️ تحذير: تقلب مفرط — خطر متزايد" : ""}

📈 آخر 5 شموع:
${last5}
${newsContext}
ملاحظة: الاتجاه الرئيسي ${trendFilter?.allowsBuy ? "📈 صاعد" : "📉 هابط"} — ${trendFilter?.allowsBuy ? "يفضّل الشراء" : "يفضّل البيع"}.`.trim();

        const systemPrompt = `أنت محلل أسواق مالية خبير ومتخصص في الفوركس والذهب والعملات الرقمية. ستحصل على تحليل شامل يتضمن مؤشرات تقنية متقدمة + إشارات من 7 استراتيجيات تداول + نتائج 4 فلاتر تأكيد + أخبار اقتصادية عالية التأثير.

مهمتك: دمج جميع هذه المعطيات وإعطاء توصية نهائية متكاملة مع الالتزام بالقواعد التالية:
1. توافق الاستراتيجيات (هل الأغلبية تشير لنفس الاتجاه؟)
2. الفلاتر (هل التوقيت والتقلب والاتجاه الرئيسي مناسبان؟)
3. قوة الإشارة الإجمالية
4. 🏛️ قاعدة الدعم والمقاومة الحتمية: إذا كان السعر عند مستوى دعم متكرر → لا تُعطِ SELL. إذا كان عند مقاومة متكررة → لا تُعطِ BUY.
5. 📰 الأخبار الاقتصادية: إذا كانت هناك أخبار عالية التأثير قريبة (خلال ساعتين) → ارفع مستوى المخاطرة وقلّل الثقة.
6. حدد مستويات فيبوناتشي (38.2%, 50%, 61.8%) بدقة وحدد مناطق الدعم والمقاومة الديناميكية.
7. قيّم نسبة المخاطرة للعائد (Risk:Reward Ratio) — يفضل 1:2 أو أفضل.

يجب أن ترد فقط بتنسيق JSON صحيح:
{
  "signal": "BUY" أو "SELL" أو "HOLD",
  "confidence": رقم من 0 إلى 100,
  "reasoning": "تحليل مفصل 4-6 جمل يذكر الاستراتيجيات والفلاتر والأخبار الاقتصادية ومستويات الدعم/المقاومة ونسبة المخاطرة",
  "entryZone": "مستوى الدخول المقترح",
  "stopLoss": "وقف الخسارة",
  "takeProfit": "جني الأرباح",
  "risk": "LOW" أو "MEDIUM" أو "HIGH",
  "riskReward": "نسبة المخاطرة:العائد مثل 1:2.5"
}

لا تُرجع أي نص خارج JSON. هذا تحليل تعليمي فقط.`;

        const providers: AIProvider[] = ["claude", "geminiPro", "deepseek"];

        const settled = await Promise.allSettled(
          providers.map(async (provider) => {
            if (!isProviderAvailable(provider)) {
              return {
                provider, providerName: PROVIDER_CONFIGS[provider].name,
                icon: PROVIDER_CONFIGS[provider].icon, color: PROVIDER_CONFIGS[provider].color,
                signal: "HOLD" as const, confidence: 0, reasoning: "المزود غير متاح — مفتاح API غير مضبوط",
                entryZone: "-", stopLoss: "-", takeProfit: "-", risk: "LOW" as const,
                duration: 0, available: false, error: "API key not configured",
              };
            }
            const start = Date.now();
            const res = await callProvider(provider, systemPrompt, marketContext);
            const duration = Date.now() - start;

            let jsonStr = res.content.trim();
            const fenced = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
            if (fenced) jsonStr = fenced[1].trim();
            const si = jsonStr.indexOf("{"), ei = jsonStr.lastIndexOf("}");
            if (si !== -1 && ei !== -1) jsonStr = jsonStr.slice(si, ei + 1);

            try {
              const p = JSON.parse(jsonStr);
              return {
                provider, providerName: PROVIDER_CONFIGS[provider].name,
                icon: PROVIDER_CONFIGS[provider].icon, color: PROVIDER_CONFIGS[provider].color,
                signal: (["BUY", "SELL", "HOLD"].includes(p.signal) ? p.signal : "HOLD") as "BUY" | "SELL" | "HOLD",
                confidence: Math.min(100, Math.max(0, Number(p.confidence) || 50)),
                reasoning: p.reasoning || "لا يوجد تحليل",
                entryZone: p.entryZone || "-", stopLoss: p.stopLoss || "-", takeProfit: p.takeProfit || "-",
                risk: (["LOW", "MEDIUM", "HIGH"].includes(p.risk) ? p.risk : "MEDIUM") as "LOW" | "MEDIUM" | "HIGH",
                duration, available: true, error: null,
              };
            } catch {
              return {
                provider, providerName: PROVIDER_CONFIGS[provider].name,
                icon: PROVIDER_CONFIGS[provider].icon, color: PROVIDER_CONFIGS[provider].color,
                signal: "HOLD" as const, confidence: 50, reasoning: res.content.slice(0, 300),
                entryZone: "-", stopLoss: "-", takeProfit: "-", risk: "MEDIUM" as const,
                duration, available: true, error: null,
              };
            }
          })
        );

        return {
          pair: input.pair,
          timeframe: input.timeframe,
          currentPrice,
          indicators: { rsi, sma20, sma50, sma200, macd, bb, atr, stoch, williamsR, pivots, adx },
          strategySignals,
          filterResults,
          economicNews: economicNewsItems,
          results: settled.map((r, i) => {
            if (r.status === "fulfilled") return r.value;
            return {
              provider: providers[i], providerName: PROVIDER_CONFIGS[providers[i]].name,
              icon: PROVIDER_CONFIGS[providers[i]].icon, color: PROVIDER_CONFIGS[providers[i]].color,
              signal: "HOLD" as const, confidence: 0, reasoning: (r.reason as Error).message,
              entryZone: "-", stopLoss: "-", takeProfit: "-", risk: "LOW" as const,
              duration: 0, available: false, error: (r.reason as Error).message,
            };
          }),
        };
      }),

    // ── Auto Signal Confluence — Multi-Timeframe Confluence Detection ─────────
    // Scans all pairs across 1M/5M/15M simultaneously
    // Sends Telegram alert ONLY when signals align across all 3 timeframes
    autoSignalConfluence: protectedProcedure
      .input(z.object({
        pairs: z.array(z.string()).default(["EURUSD", "USDJPY", "GBPUSD", "GBPJPY", "USDCHF", "AUDUSD", "NZDUSD", "USDCAD", "EURGBP", "EURJPY", "EURCHF", "AUDCAD", "XAUUSD", "XAGUSD", "BTCUSD", "ETHUSD", "USOIL", "US30"]),
      }))
      .mutation(async ({ input, ctx }) => {
        const symbolMap: Record<string, string> = {
          EURUSD: "EUR/USD", USDJPY: "USD/JPY", GBPUSD: "GBP/USD",
          GBPJPY: "GBP/JPY", USDCHF: "USD/CHF", AUDUSD: "AUD/USD",
          NZDUSD: "NZD/USD", USDCAD: "USD/CAD",
          EURGBP: "EUR/GBP", EURJPY: "EUR/JPY", EURCHF: "EUR/CHF", AUDCAD: "AUD/CAD",
          XAUUSD: "XAU/USD", XAGUSD: "XAG/USD",
          BTCUSD: "BTC/USD", ETHUSD: "ETH/USD",
          USOIL: "CL", US30: "DJIA",
        };
        const flagMap: Record<string, string> = {
          EURUSD: "🇪🇺🇺🇸", USDJPY: "🇺🇸🇯🇵", GBPUSD: "🇬🇧🇺🇸",
          GBPJPY: "🇬🇧🇯🇵", USDCHF: "🇺🇸🇨🇭", AUDUSD: "🇦🇺🇺🇸",
          NZDUSD: "🇳🇿🇺🇸", USDCAD: "🇺🇸🇨🇦",
          EURGBP: "🇪🇺🇬🇧", EURJPY: "🇪🇺🇯🇵", EURCHF: "🇪🇺🇨🇭", AUDCAD: "🇦🇺🇨🇦",
          XAUUSD: "🥇", XAGUSD: "🥈",
          BTCUSD: "₿", ETHUSD: "⟠",
          USOIL: "🛢️", US30: "🏛️",
        };

        const timeframes = ["1min", "5min", "15min"] as const;
        const alerts: Array<{
          pair: string; flag: string; signal: "BUY" | "SELL";
          confidence: number; price: string;
          tf1: { signal: string; buys: number; sells: number; rsi: number; strength: number };
          tf5: { signal: string; buys: number; sells: number; rsi: number; strength: number };
          tf15: { signal: string; buys: number; sells: number; rsi: number; strength: number };
          adxStrength: number;
          stochK: number;
          pivotLevel: string;
        }> = [];

        // Scan each pair across 3 timeframes
        for (const pair of input.pairs) {
          const symbol = symbolMap[pair];
          if (!symbol) continue;

          try {
            // Fetch all 3 timeframes in parallel
            const [res1, res5, res15] = await Promise.all(
              timeframes.map(async (tf) => {
                const url = `https://api.twelvedata.com/time_series?symbol=${encodeURIComponent(symbol)}&interval=${tf}&outputsize=60&apikey=__API_KEY__`;
                const r = await fetch(url, { signal: AbortSignal.timeout(12000) });
                return r.json() as Promise<any>;
              })
            );

            const analyzeFrame = (data: any) => {
              if (data.status === "error" || !data.values) return null;
              const candles = [...data.values].reverse() as any[];
              const closes = candles.map((c: any) => parseFloat(c.close));
              const highs = candles.map((c: any) => parseFloat(c.high));
              const lows = candles.map((c: any) => parseFloat(c.low));
              const price = closes[closes.length - 1];

              const rsi = calcRSI(closes);
              const sma20 = calcSMA(closes, 20);
              const sma50 = calcSMA(closes, 50);
              const sma200 = closes.length >= 200 ? calcSMA(closes, 200) : null;
              const macd = calcMACD(closes);
              const bb = calcBB(closes);
              const atr = calcATR(highs, lows, closes);
              const stoch = calcStochastic(closes, highs, lows);
              const adxVal = calcADX(highs, lows, closes);
              const pivotsVal = calcPivotPoints(highs, lows, closes);

              const strategies = calcStrategies(closes, highs, lows, sma20, sma50, sma200, rsi, macd, bb, atr, stoch, calcWilliamsR(closes, highs, lows), adxVal, pivotsVal);
              const buys = strategies.filter(s => s.signal === "BUY").length;
              const sells = strategies.filter(s => s.signal === "SELL").length;
              const dominant = buys > sells ? "BUY" : sells > buys ? "SELL" : "NEUTRAL";
              const nonNeutral = strategies.filter(s => s.signal !== "NEUTRAL");
              const avgStr = nonNeutral.length ? Math.round(nonNeutral.reduce((a, s) => a + s.strength, 0) / nonNeutral.length) : 0;

              return { price, rsi, signal: dominant, buys, sells, strength: avgStr, adx: adxVal.adx, stochK: stoch.k, pivot: pivotsVal.pivot };
            };

            const f1 = analyzeFrame(res1);
            const f5 = analyzeFrame(res5);
            const f15 = analyzeFrame(res15);

            if (!f1 || !f5 || !f15) continue;

            // Check confluence: all 3 timeframes agree on direction
            const allBuy = f1.signal === "BUY" && f5.signal === "BUY" && f15.signal === "BUY";
            const allSell = f1.signal === "SELL" && f5.signal === "SELL" && f15.signal === "SELL";

            if (!allBuy && !allSell) continue;

            // Calculate combined confidence
            const avgStrength = Math.round((f1.strength + f5.strength + f15.strength) / 3);
            const totalBuys = f1.buys + f5.buys + f15.buys;
            const totalSells = f1.sells + f5.sells + f15.sells;
            const totalStrategies = totalBuys + totalSells;
            const dominantCount = allBuy ? totalBuys : totalSells;
            const confidence = Math.min(95, Math.round((dominantCount / Math.max(totalStrategies, 1)) * 100 * 0.85 + avgStrength * 0.15));

            const decimals = pair === "BTCUSD" ? 1 : pair === "XAUUSD" ? 2 : pair === "XAGUSD" ? 3 : pair.includes("JPY") ? 3 : 5;

            // Determine pivot level context
            const pivotLevel = f15.price > f15.pivot ? `فوق Pivot (${f15.pivot.toFixed(decimals)})` : `تحت Pivot (${f15.pivot.toFixed(decimals)})`;

            alerts.push({
              pair,
              flag: flagMap[pair] || "📊",
              signal: allBuy ? "BUY" : "SELL",
              confidence,
              price: f15.price.toFixed(decimals),
              tf1: { signal: f1.signal, buys: f1.buys, sells: f1.sells, rsi: f1.rsi, strength: f1.strength },
              tf5: { signal: f5.signal, buys: f5.buys, sells: f5.sells, rsi: f5.rsi, strength: f5.strength },
              tf15: { signal: f15.signal, buys: f15.buys, sells: f15.sells, rsi: f15.rsi, strength: f15.strength },
              adxStrength: f15.adx,
              stochK: f15.stochK,
              pivotLevel,
            });
          } catch (err: any) {
            console.warn(`[AutoSignal] ${pair} failed:`, err.message);
          }
        }

        // Send alerts to Telegram if any
        if (alerts.length > 0) {
          try {
            const { db } = await import("@workspace/db");
            const { telegramBots } = await import("@workspace/db/schema");
            const { eq } = await import("drizzle-orm");

            const bots = await db.select().from(telegramBots).where(eq(telegramBots.userId, ctx.user.id)).limit(1);
            const bot = bots[0];

            if (bot?.isActive && bot.botToken) {
              const chatId = process.env.TELEGRAM_OWNER_CHAT_ID;
              if (chatId) {
                for (const alert of alerts) {
                  const sigEmoji = alert.signal === "BUY" ? "🟢" : "🔴";
                  const sigLabel = alert.signal === "BUY" ? "شراء" : "بيع";
                  const now = new Date();
                  const utcTime = now.toISOString().slice(11, 16) + " UTC";

                  const lines = [
                    `🚨 <b>إشارة تلقائية — تقاطع 3 فريمات</b>`,
                    ``,
                    `${alert.flag} <b>${alert.pair.replace(/(.{3})(.{3})/, "$1/$2")}</b> | ${sigEmoji} <b>${sigLabel}</b>`,
                    `💰 السعر: <code>${alert.price}</code>  ⏱ ${utcTime}`,
                    `━━━━ توافق الفريمات ━━━━`,
                    `⚡ 1M: ${alert.tf1.signal === "BUY" ? "🟢" : "🔴"} ${alert.tf1.buys}/${alert.tf1.buys + alert.tf1.sells} استراتيجية | RSI ${alert.tf1.rsi.toFixed(1)} | قوة ${alert.tf1.strength}%`,
                    `🕐 5M: ${alert.tf5.signal === "BUY" ? "🟢" : "🔴"} ${alert.tf5.buys}/${alert.tf5.buys + alert.tf5.sells} استراتيجية | RSI ${alert.tf5.rsi.toFixed(1)} | قوة ${alert.tf5.strength}%`,
                    `🕒 15M: ${alert.tf15.signal === "BUY" ? "🟢" : "🔴"} ${alert.tf15.buys}/${alert.tf15.buys + alert.tf15.sells} استراتيجية | RSI ${alert.tf15.rsi.toFixed(1)} | قوة ${alert.tf15.strength}%`,
                    `━━━━ التأكيدات ━━━━`,
                    `💪 ADX: ${alert.adxStrength.toFixed(1)} ${alert.adxStrength > 25 ? "📈 اتجاه قوي" : "➡️ ضعيف"}`,
                    `🔄 Stochastic: ${alert.stochK.toFixed(1)} ${alert.stochK > 80 ? "⚠️ ذروة شراء" : alert.stochK < 20 ? "⚠️ ذروة بيع" : "✅"}`,
                    `📍 ${alert.pivotLevel}`,
                    `━━━━━━━━━━━━━━━━━━━━`,
                    `┌──────────────────────────┐`,
                    `│ ${sigEmoji} توافق: <b>${sigLabel}</b>    ثقة: <b>${alert.confidence}%</b> │`,
                    `└──────────────────────────┘`,
                    ``,
                    `⚠️ للأغراض التعليمية فقط — ليس نصيحة مالية`,
                  ];

                  await fetch(`https://api.telegram.org/bot${bot.botToken}/sendMessage`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ chat_id: chatId, text: lines.join("\n"), parse_mode: "HTML" }),
                    signal: AbortSignal.timeout(10000),
                  });
                }
              }
            }
          } catch (err: any) {
            console.warn("[AutoSignal] Telegram send failed:", err.message);
          }
        }

        return {
          alerts,
          scannedAt: new Date().toISOString(),
          totalPairs: input.pairs.length,
          confluenceFound: alerts.length,
        };
      }),
  }),

  // ==================== System ====================
  system: router({
    health: publicProcedure.query(() => ({ status: "ok", timestamp: new Date().toISOString() })),

    getAvailableAgents: publicProcedure.query(() => [
      { id: "default", name: "HAYO Default", description: "المساعد الذكي الافتراضي", icon: "🤖" },
      { id: "code", name: "Code Agent", description: "متخصص في البرمجة", icon: "💻" },
      { id: "research", name: "Research Agent", description: "بحث وتحليل المعلومات", icon: "🔍" },
      { id: "writer", name: "Writer Agent", description: "كتابة وتحرير المحتوى", icon: "✍️" },
    ]),

    makeAdmin: adminProcedure
      .input(z.object({ userId: z.number() }))
      .mutation(async ({ input }) => {
        const { db } = await import("@workspace/db");
        const { users } = await import("@workspace/db/schema");
        const { eq } = await import("drizzle-orm");
        await db.update(users).set({ role: "admin", updatedAt: new Date() }).where(eq(users.id, input.userId));
        return { success: true };
      }),
  }),

  
  // ==================== Model Instructions ====================
  modelInstructions: router({
    getAll: adminProcedure.query(async () => {
      const { getAllInstructions } = await import("./system-prompts.js");
      return getAllInstructions();
    }),
    get: protectedProcedure
      .input(z.object({ modelId: z.string() }))
      .query(async ({ input }) => {
        const { getModelInstruction } = await import("./system-prompts.js");
        return { modelId: input.modelId, instruction: getModelInstruction(input.modelId) };
      }),
    update: adminProcedure
      .input(z.object({ modelId: z.string(), instruction: z.string().max(5000) }))
      .mutation(async ({ input }) => {
        const { setModelInstruction } = await import("./system-prompts.js");
        setModelInstruction(input.modelId, input.instruction);
        return { success: true, modelId: input.modelId };
      }),
    reset: adminProcedure
      .input(z.object({ modelId: z.string() }))
      .mutation(async ({ input }) => {
        const { resetModelInstruction, getModelInstruction } = await import("./system-prompts.js");
        resetModelInstruction(input.modelId);
        return { success: true, instruction: getModelInstruction(input.modelId) };
      }),
  }),

// ==================== Reverse Engineer ====================
  reverseEngineer: reverseEngineerRouter,
  aiAgent: aiAgentRouter,
});

export type AppRouter = typeof appRouter;
