/**
 * HAYO Trading Bot — Button-driven + Auto-Signals (owner-only)
 *
 * Manual flow:  /start → [Pair] → [Timeframe] → [Analysis type] → Results
 * Auto-signals: Periodic scan → strategies ≥ threshold → AI check → send alert
 */

import TelegramBot from "node-telegram-bot-api";
import { callProvider, isProviderAvailable, PROVIDER_CONFIGS, type AIProvider } from "../hayo/providers";
import { getTwelveDataKey, markKeyExhausted, isRateLimitError, rotateToNextKey, checkAndMarkIfDailyExhausted, getKeyStats } from "../lib/twelvedata-keys";

// ─── Config ───────────────────────────────────────────────────────────
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const OWNER_ID  = process.env.TELEGRAM_OWNER_CHAT_ID;

interface PairInfo { tdSymbol: string; label: string; flag: string; decimals: number }
const PAIRS: Record<string, PairInfo> = {
  EURUSD: { tdSymbol: "EUR/USD", label: "EUR/USD", flag: "🇪🇺🇺🇸", decimals: 5 },
  USDJPY: { tdSymbol: "USD/JPY", label: "USD/JPY", flag: "🇺🇸🇯🇵", decimals: 3 },
  GBPUSD: { tdSymbol: "GBP/USD", label: "GBP/USD", flag: "🇬🇧🇺🇸", decimals: 5 },
  GBPJPY: { tdSymbol: "GBP/JPY", label: "GBP/JPY", flag: "🇬🇧🇯🇵", decimals: 3 },
  USDCHF: { tdSymbol: "USD/CHF", label: "USD/CHF", flag: "🇺🇸🇨🇭", decimals: 5 },
  AUDUSD: { tdSymbol: "AUD/USD", label: "AUD/USD", flag: "🇦🇺🇺🇸", decimals: 5 },
  NZDUSD: { tdSymbol: "NZD/USD", label: "NZD/USD", flag: "🇳🇿🇺🇸", decimals: 5 },
  USDCAD: { tdSymbol: "USD/CAD", label: "USD/CAD", flag: "🇺🇸🇨🇦", decimals: 5 },
  EURGBP: { tdSymbol: "EUR/GBP", label: "EUR/GBP", flag: "🇪🇺🇬🇧", decimals: 5 },
  EURJPY: { tdSymbol: "EUR/JPY", label: "EUR/JPY", flag: "🇪🇺🇯🇵", decimals: 3 },
  EURCHF: { tdSymbol: "EUR/CHF", label: "EUR/CHF", flag: "🇪🇺🇨🇭", decimals: 5 },
  AUDCAD: { tdSymbol: "AUD/CAD", label: "AUD/CAD", flag: "🇦🇺🇨🇦", decimals: 5 },
  XAUUSD: { tdSymbol: "XAU/USD", label: "XAU/USD", flag: "🥇",     decimals: 2 },
  XAGUSD: { tdSymbol: "XAG/USD", label: "XAG/USD", flag: "🥈",     decimals: 4 },
  BTCUSD: { tdSymbol: "BTC/USD", label: "BTC/USD", flag: "₿",      decimals: 2 },
  ETHUSD: { tdSymbol: "ETH/USD", label: "ETH/USD", flag: "⟠",      decimals: 2 },
  USOIL:  { tdSymbol: "CL",     label: "US Oil",   flag: "🛢️",     decimals: 2 },
  US30:   { tdSymbol: "DJIA",   label: "US30/DJI", flag: "🏛️",     decimals: 0 },
};

// TwelveData interval config per bot timeframe key
interface TfConfig { interval: string; outputsize: number; label: string }
const TIMEFRAMES: Record<string, TfConfig> = {
  "1m":  { interval: "1min",  outputsize: 60,  label: "1 دقيقة"  },
  "5m":  { interval: "5min",  outputsize: 60,  label: "5 دقائق"  },
  "15m": { interval: "15min", outputsize: 60,  label: "15 دقيقة" },
  "30m": { interval: "30min", outputsize: 60,  label: "30 دقيقة" },
  "1h":  { interval: "1h",    outputsize: 60,  label: "ساعة"     },
};

// ─── Auto-Signal Config ───────────────────────────────────────────────
interface AutoConfig {
  enabled: boolean;
  minConsensus: number;       // minimum % strategies agreement (e.g. 75)
  minAIConfidence: number;    // minimum avg AI confidence (e.g. 70)
  pairs: string[];            // pairs to scan
  timeframes: string[];       // timeframes to scan
  intervalMinutes: number;    // scan every X minutes
}

const defaultAutoConfig: AutoConfig = {
  enabled: false,
  minConsensus: 75,
  minAIConfidence: 70,
  pairs: Object.keys(PAIRS),
  timeframes: ["15m", "1h"],
  intervalMinutes: 30,
};

let autoConfig: AutoConfig = { ...defaultAutoConfig };
let autoScanTimer: NodeJS.Timeout | null = null;

const SIGNAL_COOLDOWN_MS = 4 * 60 * 60 * 1000;

// ─── Session State ────────────────────────────────────────────────────
// Declared inside startTelegramBot so each bot instance has independent state
interface Session { pair?: string; tf?: string; settingsContext?: string }

// ─── Keyboards ────────────────────────────────────────────────────────
function pairsKeyboard(): TelegramBot.InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [{ text: "━━ 💱 العملات الرئيسية ━━", callback_data: "noop" }],
      [
        { text: "🇪🇺🇺🇸 EUR/USD", callback_data: "pair:EURUSD" },
        { text: "🇺🇸🇯🇵 USD/JPY", callback_data: "pair:USDJPY" },
        { text: "🇬🇧🇺🇸 GBP/USD", callback_data: "pair:GBPUSD" },
      ],
      [
        { text: "🇬🇧🇯🇵 GBP/JPY", callback_data: "pair:GBPJPY" },
        { text: "🇺🇸🇨🇭 USD/CHF", callback_data: "pair:USDCHF" },
        { text: "🇦🇺🇺🇸 AUD/USD", callback_data: "pair:AUDUSD" },
      ],
      [
        { text: "🇳🇿🇺🇸 NZD/USD", callback_data: "pair:NZDUSD" },
        { text: "🇺🇸🇨🇦 USD/CAD", callback_data: "pair:USDCAD" },
      ],
      [{ text: "━━ 🔀 الأزواج المتقاطعة ━━", callback_data: "noop" }],
      [
        { text: "🇪🇺🇬🇧 EUR/GBP", callback_data: "pair:EURGBP" },
        { text: "🇪🇺🇯🇵 EUR/JPY", callback_data: "pair:EURJPY" },
        { text: "🇪🇺🇨🇭 EUR/CHF", callback_data: "pair:EURCHF" },
      ],
      [
        { text: "🇦🇺🇨🇦 AUD/CAD", callback_data: "pair:AUDCAD" },
      ],
      [{ text: "━━ 🥇 المعادن والسلع ━━", callback_data: "noop" }],
      [
        { text: "🥇 ذهب XAU", callback_data: "pair:XAUUSD" },
        { text: "🥈 فضة XAG", callback_data: "pair:XAGUSD" },
        { text: "🛢️ نفط Oil", callback_data: "pair:USOIL" },
      ],
      [{ text: "━━ 📊 كريبتو ومؤشرات ━━", callback_data: "noop" }],
      [
        { text: "₿ BTC/USD", callback_data: "pair:BTCUSD" },
        { text: "⟠ ETH/USD", callback_data: "pair:ETHUSD" },
        { text: "🏛️ US30/DJI", callback_data: "pair:US30" },
      ],
      [
        { text: `📡 إشارات تلقائية ${autoConfig.enabled ? "✅" : "❌"}`, callback_data: "auto:menu" },
        { text: `🎯 التطابق ${convergenceConfig.enabled ? "✅" : "❌"}`, callback_data: "conv:menu" },
      ],
    ],
  };
}

function timeframesKeyboard(): TelegramBot.InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [
        { text: "1 دقيقة",  callback_data: "tf:1m" },
        { text: "5 دقائق",  callback_data: "tf:5m" },
        { text: "15 دقيقة", callback_data: "tf:15m" },
      ],
      [
        { text: "30 دقيقة", callback_data: "tf:30m" },
        { text: "ساعة كاملة", callback_data: "tf:1h" },
      ],
      [{ text: "◀️ تغيير الزوج", callback_data: "back:pairs" }],
    ],
  };
}

function analysisTypeKeyboard(): TelegramBot.InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [{ text: "⚡ تقني فوري (بدون AI)", callback_data: "analyze:quick" }],
      [{ text: "🤖 تحليل كامل بالذكاء الاصطناعي", callback_data: "analyze:full" }],
      [
        { text: "◀️ تغيير الإطار", callback_data: "back:timeframes" },
        { text: "🔄 تغيير الزوج",  callback_data: "back:pairs" },
      ],
    ],
  };
}

function afterResultKeyboard(): TelegramBot.InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [
        { text: "⚡ تقني مجدداً",  callback_data: "analyze:quick" },
        { text: "🤖 AI مجدداً",    callback_data: "analyze:full" },
      ],
      [
        { text: "🔄 تغيير الإطار", callback_data: "back:timeframes" },
        { text: "🏠 زوج جديد",    callback_data: "back:pairs" },
      ],
    ],
  };
}

// ─── Auto-Signal Settings Keyboards ──────────────────────────────────
function autoMenuKeyboard(): TelegramBot.InlineKeyboardMarkup {
  const c = autoConfig;
  const pf: Record<string, string> = {
    EURUSD:"🇪🇺🇺🇸", USDJPY:"🇺🇸🇯🇵", GBPUSD:"🇬🇧🇺🇸", GBPJPY:"🇬🇧🇯🇵",
    USDCHF:"🇺🇸🇨🇭", AUDUSD:"🇦🇺🇺🇸", NZDUSD:"🇳🇿🇺🇸", USDCAD:"🇺🇸🇨🇦",
    EURGBP:"🇪🇺🇬🇧", EURJPY:"🇪🇺🇯🇵", EURCHF:"🇪🇺🇨🇭", AUDCAD:"🇦🇺🇨🇦",
    XAUUSD:"🥇", XAGUSD:"🥈", BTCUSD:"₿", ETHUSD:"⟠", USOIL:"🛢️", US30:"🏛️",
  };
  const pairLabel: Record<string, string> = {
    EURUSD:"EUR/USD", USDJPY:"USD/JPY", GBPUSD:"GBP/USD", GBPJPY:"GBP/JPY",
    USDCHF:"USD/CHF", AUDUSD:"AUD/USD", NZDUSD:"NZD/USD", USDCAD:"USD/CAD",
    EURGBP:"EUR/GBP", EURJPY:"EUR/JPY", EURCHF:"EUR/CHF", AUDCAD:"AUD/CAD",
    XAUUSD:"XAU/USD", XAGUSD:"XAG/USD", BTCUSD:"BTC/USD", ETHUSD:"ETH/USD",
    USOIL:"Oil", US30:"US30",
  };
  const pb = (p: string) => ({ text: `${c.pairs.includes(p)?"✅ ":""}${pf[p]||""}${pairLabel[p]||p}`, callback_data: `auto:pair:${p}` });
  const allPairsCount = c.pairs.length;
  const totalPairs = Object.keys(PAIRS).length;

  return {
    inline_keyboard: [
      [{ text: `${c.enabled ? "🔴 إيقاف الإشارات" : "🟢 تفعيل الإشارات"}`, callback_data: "auto:toggle" }],
      [{ text: `━━ الحد الأدنى للتوافق: ${c.minConsensus}% ━━`, callback_data: "auto:noop" }],
      [
        { text: `${c.minConsensus===65?"✅ ":""}65%`, callback_data: "auto:cons:65" },
        { text: `${c.minConsensus===75?"✅ ":""}75%`, callback_data: "auto:cons:75" },
        { text: `${c.minConsensus===85?"✅ ":""}85%`, callback_data: "auto:cons:85" },
      ],
      [{ text: `━━ ثقة AI الأدنى: ${c.minAIConfidence}% ━━`, callback_data: "auto:noop" }],
      [
        { text: `${c.minAIConfidence===60?"✅ ":""}60%`, callback_data: "auto:aiconf:60" },
        { text: `${c.minAIConfidence===70?"✅ ":""}70%`, callback_data: "auto:aiconf:70" },
        { text: `${c.minAIConfidence===80?"✅ ":""}80%`, callback_data: "auto:aiconf:80" },
      ],
      [{ text: `━━ الأزواج المراقَبة (${allPairsCount}/${totalPairs}) ━━`, callback_data: "auto:noop" }],
      [{ text: `${allPairsCount===totalPairs?"✅ ":""}تحديد/إلغاء الكل`, callback_data: "auto:pair:ALL" }],
      [pb("EURUSD"), pb("USDJPY"), pb("GBPUSD")],
      [pb("GBPJPY"), pb("USDCHF"), pb("AUDUSD")],
      [pb("NZDUSD"), pb("USDCAD"), pb("EURGBP")],
      [pb("EURJPY"), pb("EURCHF"), pb("AUDCAD")],
      [pb("XAUUSD"), pb("XAGUSD"), pb("BTCUSD")],
      [pb("ETHUSD"), pb("USOIL"), pb("US30")],
      [{ text: "━━ الإطارات الزمنية ━━", callback_data: "auto:noop" }],
      [
        { text: `${c.timeframes.includes("1m") ?"✅ ":""}1م`,   callback_data: "auto:tf:1m" },
        { text: `${c.timeframes.includes("5m") ?"✅ ":""}5م`,   callback_data: "auto:tf:5m" },
        { text: `${c.timeframes.includes("15m")?"✅ ":""}15م`,  callback_data: "auto:tf:15m" },
      ],
      [
        { text: `${c.timeframes.includes("30m")?"✅ ":""}30م`,  callback_data: "auto:tf:30m" },
        { text: `${c.timeframes.includes("1h") ?"✅ ":""}1س`,   callback_data: "auto:tf:1h" },
      ],
      [{ text: "━━ فترة الفحص التلقائي ━━", callback_data: "auto:noop" }],
      [
        { text: `${c.intervalMinutes===1 ?"✅ ":""}1د`,   callback_data: "auto:interval:1" },
        { text: `${c.intervalMinutes===5 ?"✅ ":""}5د`,   callback_data: "auto:interval:5" },
        { text: `${c.intervalMinutes===15?"✅ ":""}15د`,  callback_data: "auto:interval:15" },
        { text: `${c.intervalMinutes===30?"✅ ":""}30د`,  callback_data: "auto:interval:30" },
      ],
      [{ text: "◀️ رجوع للقائمة الرئيسية", callback_data: "back:pairs" }],
    ],
  };
}

// ─── Indicator Helpers ────────────────────────────────────────────────
function smaN(arr: number[], n: number) {
  if (arr.length < n) return arr[arr.length - 1] ?? 0;
  return arr.slice(-n).reduce((a, b) => a + b, 0) / n;
}
function emaN(arr: number[], n: number) {
  if (!arr.length) return 0;
  const k = 2 / (n + 1);
  let e = arr[0];
  for (let i = 1; i < arr.length; i++) e = arr[i] * k + e * (1 - k);
  return e;
}
function calcRSI(closes: number[], period = 14) {
  if (closes.length < period + 1) return 50;
  let g = 0, l = 0;
  for (let i = closes.length - period; i < closes.length; i++) {
    const d = closes[i] - closes[i - 1];
    if (d > 0) g += d; else l -= d;
  }
  const ag = g / period, al = l / period;
  return al === 0 ? 100 : 100 - 100 / (1 + ag / al);
}
function calcMACD(closes: number[]) {
  const m = emaN(closes, 12) - emaN(closes, 26);
  const s = m * 0.88;
  return { macd: m, signal: s, histogram: m - s };
}
function calcBB(closes: number[], period = 20, mult = 2) {
  const mid = smaN(closes, period);
  const sl  = closes.slice(-period);
  const sd  = Math.sqrt(sl.reduce((a, v) => a + Math.pow(v - mid, 2), 0) / period);
  return { upper: mid + mult * sd, middle: mid, lower: mid - mult * sd };
}
function calcATR(highs: number[], lows: number[], closes: number[], period = 14) {
  const trs: number[] = [];
  for (let i = 1; i < highs.length; i++)
    trs.push(Math.max(highs[i] - lows[i], Math.abs(highs[i] - closes[i-1]), Math.abs(lows[i] - closes[i-1])));
  return smaN(trs, period);
}

// ─── Strategy Engine ──────────────────────────────────────────────────
interface Sig { name: string; emoji: string; signal: "BUY"|"SELL"|"NEUTRAL"; strength: number; desc: string }
interface Flt { name: string; emoji: string; passed: boolean; desc: string }

function calcStrategies(
  closes: number[], highs: number[], lows: number[],
  sma20: number, sma50: number, sma200: number|null,
  RSI: number, MACD: ReturnType<typeof calcMACD>,
  BB: ReturnType<typeof calcBB>, ATR: number,
): Sig[] {
  const price = closes[closes.length - 1];
  const prev  = closes[closes.length - 2] || price;
  const res: Sig[] = [];

  // 1 — Trend Following
  let ts: "BUY"|"SELL"|"NEUTRAL" = "NEUTRAL", tStr = 0;
  if (sma200) {
    if (price>sma20&&sma20>sma50&&sma50>sma200){ts="BUY";tStr=88;}
    else if(price<sma20&&sma20<sma50&&sma50<sma200){ts="SELL";tStr=88;}
    else if(price>sma20&&sma20>sma50){ts="BUY";tStr=65;}
    else if(price<sma20&&sma20<sma50){ts="SELL";tStr=65;}
  } else {
    if(price>sma20&&sma20>sma50){ts="BUY";tStr=70;}
    else if(price<sma20&&sma20<sma50){ts="SELL";tStr=70;}
  }
  res.push({ name:"تتبع الاتجاه", emoji:"🎯", signal:ts, strength:tStr,
    desc:ts==="BUY"?"SMA20>50>200 صاعد":ts==="SELL"?"SMA20<50<200 هابط":"لا توافق" });

  // 2 — Breakout (Bollinger)
  let bs: "BUY"|"SELL"|"NEUTRAL" = "NEUTRAL", bStr = 0;
  const bbW = (BB.upper-BB.lower)/BB.middle*100;
  if(bbW>=0.8){
    if(prev<=BB.lower&&price>BB.lower){bs="BUY";bStr=82;}
    else if(prev>=BB.upper&&price<BB.upper){bs="SELL";bStr=82;}
    else if(price<BB.lower){bs="BUY";bStr=68;}
    else if(price>BB.upper){bs="SELL";bStr=68;}
  }
  res.push({ name:"اختراق Bollinger", emoji:"💥", signal:bs, strength:bStr,
    desc:bbW<0.8?"نطاق ضيق — انتظار":bs==="BUY"?"ارتداد من النطاق السفلي":bs==="SELL"?"ارتداد من النطاق العلوي":"داخل النطاق" });

  // 3 — RSI
  let rs: "BUY"|"SELL"|"NEUTRAL" = "NEUTRAL", rStr = 0;
  if(RSI<20){rs="BUY";rStr=92;}else if(RSI<30){rs="BUY";rStr=78;}else if(RSI<38){rs="BUY";rStr=58;}
  else if(RSI>80){rs="SELL";rStr=92;}else if(RSI>70){rs="SELL";rStr=78;}else if(RSI>62){rs="SELL";rStr=58;}
  res.push({ name:"زخم RSI", emoji:"⚡", signal:rs, strength:rStr,
    desc:`RSI=${RSI.toFixed(1)} — ${RSI<30?"ذروة بيع 🔴":RSI<38?"قرب ذروة بيع":RSI>70?"ذروة شراء 🟢":RSI>62?"قرب ذروة شراء":"محايد"}` });

  // 4 — MACD
  let ms: "BUY"|"SELL"|"NEUTRAL" = "NEUTRAL", mStr = 0;
  if(MACD.histogram>0&&MACD.macd>MACD.signal){ms="BUY";mStr=Math.min(88,50+Math.round(Math.abs(MACD.histogram)/(Math.abs(MACD.macd)||1)*80));}
  else if(MACD.histogram<0&&MACD.macd<MACD.signal){ms="SELL";mStr=Math.min(88,50+Math.round(Math.abs(MACD.histogram)/(Math.abs(MACD.macd)||1)*80));}
  res.push({ name:"تقاطع MACD", emoji:"📊", signal:ms, strength:mStr,
    desc:`MACD ${MACD.macd>MACD.signal?"فوق":"تحت"} الإشارة` });

  // 5 — Scalping
  const dist=(price-sma20)/sma20*100;
  let ss: "BUY"|"SELL"|"NEUTRAL" = "NEUTRAL", sStr = 0;
  if(dist<-0.20){ss="BUY";sStr=75;}else if(dist<-0.10){ss="BUY";sStr=58;}
  else if(dist>0.20){ss="SELL";sStr=75;}else if(dist>0.10){ss="SELL";sStr=58;}
  res.push({ name:"سكالبينج", emoji:"⚡", signal:ss, strength:sStr,
    desc:`بُعد عن SMA20: ${dist>=0?"+":""}${dist.toFixed(3)}%` });

  // 6 — Swing
  const dSMA50=Math.abs(price-sma50)/sma50*100, nearSMA50=dSMA50<0.18;
  let ws: "BUY"|"SELL"|"NEUTRAL" = "NEUTRAL", wStr = 0;
  if(nearSMA50&&sma20>sma50){ws="BUY";wStr=74;}else if(nearSMA50&&sma20<sma50){ws="SELL";wStr=74;}
  else if(price>sma50&&RSI<48){ws="BUY";wStr=62;}else if(price<sma50&&RSI>52){ws="SELL";wStr=62;}
  res.push({ name:"سوينغ", emoji:"🌊", signal:ws, strength:wStr,
    desc:nearSMA50?`قرب SMA50 — انعكاس محتمل`:`انتظار تصحيح نحو SMA50` });

  // 7 — Support & Resistance
  {
    const pd=price>100?2:price>10?3:5, f5=(n:number)=>n.toFixed(pd);
    const swH:number[]=[],swL:number[]=[];
    for(let i=3;i<highs.length-3;i++){
      let isH=true,isL=true;
      for(let j=i-3;j<=i+3;j++){if(j===i)continue;if(highs[j]>=highs[i])isH=false;if(lows[j]<=lows[i])isL=false;}
      if(isH)swH.push(highs[i]);if(isL)swL.push(lows[i]);
    }
    const cluster=(lvls:number[])=>{
      const g:{p:number;c:number}[]=[];
      for(const l of lvls){const x=g.find(x=>Math.abs(x.p-l)<=ATR);if(x){x.p=(x.p*x.c+l)/(x.c+1);x.c++;}else g.push({p:l,c:1});}
      return g.map(x=>({price:x.p,touches:x.c}));
    };
    const vR=cluster(swH).filter(l=>l.price>price&&l.touches>=2).sort((a,b)=>a.price-b.price);
    const vS=cluster(swL).filter(l=>l.price<price&&l.touches>=2).sort((a,b)=>b.price-a.price);
    const nR=vR[0]??null,nS=vS[0]??null,prox=ATR*0.5;
    let srSig:"BUY"|"SELL"|"NEUTRAL"="NEUTRAL",srStr=0,srDesc="";
    if(nS&&Math.abs(price-nS.price)<=prox){
      srSig="BUY";srStr=nS.touches>=3?88:72;
      srDesc=`دعم عند ${f5(nS.price)} (${nS.touches} لمسات${nS.touches>=3?" ✅":" ⚡"})`;
    } else if(nR&&Math.abs(price-nR.price)<=prox){
      srSig="SELL";srStr=nR.touches>=3?88:72;
      srDesc=`مقاومة عند ${f5(nR.price)} (${nR.touches} لمسات${nR.touches>=3?" ✅":" ⚡"})`;
    } else {
      srDesc=`دعم: ${nS?f5(nS.price)+"("+nS.touches+"x)":"—"} | مقاومة: ${nR?f5(nR.price)+"("+nR.touches+"x)":"—"}`;
    }
    res.push({ name:"دعم ومقاومة", emoji:"🏛️", signal:srSig, strength:srStr, desc:srDesc });
  }
  return res;
}

function calcFilters(
  price:number,sma20:number,sma50:number,sma200:number|null,
  RSI:number,ATR:number,closes:number[]
):Flt[]{
  const res:Flt[]=[];
  const ref=sma200||sma50,bull=price>ref;
  res.push({name:"الاتجاه الرئيسي",emoji:"🧭",passed:true,
    desc:bull?`📈 صاعد (فوق ${sma200?"SMA200":"SMA50"})`:`📉 هابط (تحت ${sma200?"SMA200":"SMA50"})`});
  const avgM=smaN(closes.slice(-20).map((c,i,a)=>i>0?Math.abs(c-a[i-1]):0).slice(1),14);
  const ratio=avgM>0?ATR/avgM:1,hiVol=ratio>2.8;
  res.push({name:"فلتر التقلب",emoji:"📉",passed:!hiVol,
    desc:hiVol?`⚠️ تقلب مفرط (${ratio.toFixed(2)}x)`:ratio<0.35?`😴 تقلب منخفض (${ratio.toFixed(2)}x)`:`✅ طبيعي (${ratio.toFixed(2)}x)`});
  res.push({name:"تأكيد RSI",emoji:"📡",passed:true,
    desc:`RSI=${RSI.toFixed(1)} — ${RSI>45&&RSI<55?"محايد":RSI>55?"يدعم الشراء":"يدعم البيع"}`});
  const h=new Date().getUTCHours();
  const london=h>=8&&h<16,ny=h>=13&&h<21,overlap=h>=13&&h<16,active=london||ny;
  const sess=overlap?"تداخل London/NY 🔥":london?"London 🇬🇧":ny?"New York 🇺🇸":h<8?"آسيا 🌏":"بين الجلسات";
  res.push({name:"فلتر الجلسة",emoji:"🕐",passed:active,
    desc:`${sess} UTC ${String(h).padStart(2,"0")}:${String(new Date().getUTCMinutes()).padStart(2,"0")} ${active?"✅":"⚠️"}`});
  return res;
}

// ─── Market Data — TwelveData API ─────────────────────────────────────
interface CacheEntry { data: any; ts: number }
const marketCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 3 * 60 * 1000; // 3-minute cache

async function fetchMarket(pair: string, tfCfg: TfConfig) {
  const p = PAIRS[pair];
  const cacheKey = `${pair}:${tfCfg.interval}`;

  const cached = marketCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    console.log(`[Bot] Cache hit: ${cacheKey} (${Math.round((Date.now()-cached.ts)/1000)}s old)`);
    return cached.data;
  }

  let apiKey = getTwelveDataKey();
  if (!apiKey) throw new Error("TWELVE_DATA_API_KEY غير مضبوط");

  let json: any;
  for (let attempt = 0; attempt < 6; attempt++) {
    const url = `https://api.twelvedata.com/time_series?symbol=${encodeURIComponent(p.tdSymbol)}&interval=${tfCfg.interval}&outputsize=${tfCfg.outputsize}&apikey=${apiKey}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (res.status === 429) {
      rotateToNextKey();
      apiKey = getTwelveDataKey();
      await new Promise(r => setTimeout(r, 8000));
      continue;
    }
    if (!res.ok) throw new Error(`TwelveData HTTP ${res.status}`);
    json = await res.json() as any;

    if (json.status === "error" && isRateLimitError(json)) {
      const isDailyDone = await checkAndMarkIfDailyExhausted(apiKey);
      if (!isDailyDone) {
        rotateToNextKey();
        await new Promise(r => setTimeout(r, 8000));
      }
      apiKey = getTwelveDataKey();
      if (!apiKey) break;
      continue;
    }
    break;
  }

  if (json.status === "error" || !json.values || !Array.isArray(json.values)) {
    throw new Error(json.message || "لا توجد بيانات من TwelveData");
  }

  const rawCandles = [...json.values].reverse();
  if (rawCandles.length < 20) throw new Error("بيانات غير كافية من TwelveData");

  const closes = rawCandles.map((c: any) => parseFloat(c.close));
  const highs  = rawCandles.map((c: any) => parseFloat(c.high));
  const lows   = rawCandles.map((c: any) => parseFloat(c.low));

  const price  = closes[closes.length - 1];
  const dec    = p.decimals;
  const fmt    = (n: number) => n.toFixed(dec);

  const RSI    = calcRSI(closes);
  const SMA20  = smaN(closes, 20);
  const SMA50  = smaN(closes, 50);
  const SMA200 = closes.length >= 200 ? smaN(closes, 200) : null;
  const MACD   = calcMACD(closes);
  const BB     = calcBB(closes);
  const ATR    = calcATR(highs, lows, closes);
  const strategies = calcStrategies(closes, highs, lows, SMA20, SMA50, SMA200, RSI, MACD, BB, ATR);
  const filters    = calcFilters(price, SMA20, SMA50, SMA200, RSI, ATR, closes);

  const marketResult = {
    price, fmt, RSI, SMA20, SMA50, SMA200, MACD, BB, ATR,
    strategies, filters,
    datetime: rawCandles[rawCandles.length - 1].datetime,
  };

  marketCache.set(cacheKey, { data: marketResult, ts: Date.now() });
  console.log(`[Bot] TwelveData ✅ ${pair} ${tfCfg.interval} — ${closes.length} candles, price: ${fmt(price)}`);
  return marketResult;
}

// ─── Consensus Calculator ─────────────────────────────────────────────
function calcConsensus(strategies: Sig[]): { direction: "BUY"|"SELL"|"NEUTRAL"; pct: number } {
  const buys  = strategies.filter(s=>s.signal==="BUY").length;
  const sells = strategies.filter(s=>s.signal==="SELL").length;
  const total = strategies.length;
  if (buys > sells)  return { direction:"BUY",  pct: Math.round(buys/total*100) };
  if (sells > buys)  return { direction:"SELL", pct: Math.round(sells/total*100) };
  return { direction:"NEUTRAL", pct: 0 };
}

// ─── Economic News Fetcher (cached 30 min) ───────────────────────────
interface NewsEvent { currency: string; title: string; impact: string; time: string; forecast: string; previous: string; actual: string }

const PAIR_CURRENCIES: Record<string, string[]> = {
  EURUSD: ["EUR","USD"], USDJPY: ["USD","JPY"], GBPUSD: ["GBP","USD"],
  GBPJPY: ["GBP","JPY"], XAUUSD: ["USD","XAU"],
  BTCUSD: ["BTC","USD"], USDCHF: ["USD","CHF"], AUDUSD: ["AUD","USD"], XAGUSD: ["XAG","USD"],
};

// Raw news cache (single fetch, filter per-pair)
let rawNewsCache: { items: any[]; ts: number } | null = null;
const RAW_NEWS_TTL = 30 * 60 * 1000; // 30 minutes

async function fetchEconomicNews(pair: string): Promise<NewsEvent[]> {
  const related = PAIR_CURRENCIES[pair] ?? [];
  try {
    // Use cached raw news if fresh
    if (!rawNewsCache || Date.now() - rawNewsCache.ts > RAW_NEWS_TTL) {
      const url = "https://nfs.faireconomy.media/ff_calendar_thisweek.json";
      const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) return [];
      rawNewsCache = { items: await res.json() as any[], ts: Date.now() };
      console.log(`[TelegramBot] Economic news fetched from API (${rawNewsCache.items.length} events)`);
    } else {
      console.log(`[TelegramBot] Economic news from cache (${Math.round((Date.now()-rawNewsCache.ts)/60000)}m old)`);
    }

    const now = new Date();
    return rawNewsCache.items
      .filter((e:any) =>
        (e.impact === "High" || e.impact === "Medium") &&
        related.includes(e.country)
      )
      .map((e:any) => ({
        currency: e.country, title: e.title, impact: e.impact,
        time: e.time, forecast: e.forecast||"—", previous: e.previous||"—", actual: e.actual||"لم يُعلن",
      }))
      .filter((e:any) => {
        const t = new Date(`${new Date().toDateString()} ${e.time}`);
        return Math.abs(t.getTime() - now.getTime()) < 12 * 3600000;
      })
      .slice(0, 5);
  } catch { return []; }
}

// ─── AI Runner (5 models — matches platform) ──────────────────────────
async function runAI(pair: string, tf: string, d: Awaited<ReturnType<typeof fetchMarket>>, news: NewsEvent[] = []) {
  const buySigs  = d.strategies.filter(s=>s.signal==="BUY").length;
  const sellSigs = d.strategies.filter(s=>s.signal==="SELL").length;
  const avgStr   = Math.round(
    d.strategies.filter(s=>s.signal!=="NEUTRAL").reduce((a,s)=>a+s.strength,0) /
    (d.strategies.filter(s=>s.signal!=="NEUTRAL").length || 1)
  );

  // Build news context (same as router.ts)
  const newsContext = news.length > 0
    ? `\n\n📰 الأخبار الاقتصادية ذات الصلة:\n` +
      news.map(e=>`• ${e.impact==="High"?"🔴":"🟡"} ${e.currency} | ${e.title} | توقعات: ${e.forecast} | سابق: ${e.previous} | فعلي: ${e.actual}`).join("\n") +
      "\n⚠️ مهم: راعِ هذه الأخبار عند تحديد مستوى المخاطرة."
    : "";

  const ctx = `تحليل زوج ${pair} — الإطار الزمني: ${tf}
السعر الحالي: ${d.fmt(d.price)}

📊 المؤشرات التقنية:
• RSI(14): ${d.RSI.toFixed(1)} ${d.RSI<30?"(ذروة بيع ⚠️)":d.RSI>70?"(ذروة شراء ⚠️)":"(محايد)"}
• MACD: ${d.fmt(d.MACD.macd)} | Signal: ${d.fmt(d.MACD.signal)} | ${d.MACD.macd>d.MACD.signal?"📈 صاعد":"📉 هابط"}
• SMA20: ${d.fmt(d.SMA20)} ${d.price>d.SMA20?"✅ فوق":"❌ تحت"} | SMA50: ${d.fmt(d.SMA50)} ${d.price>d.SMA50?"✅ فوق":"❌ تحت"}${d.SMA200?` | SMA200: ${d.fmt(d.SMA200)} ${d.price>d.SMA200?"✅ فوق":"❌ تحت"}`:" | SMA200: بيانات غير كافية"}
• BB: أعلى ${d.fmt(d.BB.upper)} | وسط ${d.fmt(d.BB.middle)} | أسفل ${d.fmt(d.BB.lower)}
• ATR(14): ${d.fmt(d.ATR)}

🎯 إشارات الاستراتيجيات (${buySigs} شراء / ${sellSigs} بيع / ${d.strategies.length-buySigs-sellSigs} محايد):
${d.strategies.map(s=>`• ${s.emoji} ${s.name}: ${s.signal==="BUY"?"🟢 BUY":s.signal==="SELL"?"🔴 SELL":"🟡 NEUTRAL"} (قوة: ${s.strength}%) — ${s.desc}`).join("\n")}
متوسط قوة الإشارة: ${avgStr}%

🔍 الفلاتر (${d.filters.filter(f=>f.passed).length}/${d.filters.length} اجتازت):
${d.filters.map(f=>`• ${f.emoji} ${f.name}: ${f.passed?"✅":"⚠️"} — ${f.desc}`).join("\n")}${newsContext}`;

  const sys = `أنت محلل أسواق مالية خبير متخصص في الفوركس والذهب. ستحصل على تحليل شامل يتضمن مؤشرات تقنية + إشارات من 7 استراتيجيات + نتائج 4 فلاتر تأكيد${news.length>0?" + أخبار اقتصادية":""}.

مهمتك: دمج جميع هذه المعطيات وإعطاء توصية نهائية متكاملة مع الالتزام بالقواعد التالية:
1. توافق الاستراتيجيات (هل الأغلبية تشير لنفس الاتجاه؟)
2. الفلاتر (هل التوقيت والتقلب والاتجاه الرئيسي مناسبان؟)
3. قوة الإشارة الإجمالية
4. 🏛️ قاعدة حتمية: إذا كان السعر عند دعم متكرر → لا تُعطِ SELL. إذا كان عند مقاومة متكررة → لا تُعطِ BUY.
${news.some(e=>e.impact==="High")?"5. 📰 هناك أخبار عالية التأثير قريبة → ارفع مستوى المخاطرة وقلّل الثقة.":""}

يجب أن ترد فقط بتنسيق JSON صحيح:
{"signal":"BUY"|"SELL"|"HOLD","confidence":0-100,"reasoning":"تحليل 3-4 جمل يذكر الاستراتيجيات والفلاتر والأخبار","entryZone":"مستوى الدخول","stopLoss":"وقف الخسارة","takeProfit":"جني الأرباح","risk":"LOW"|"MEDIUM"|"HIGH"}

لا تُرجع أي نص خارج JSON. هذا تحليل تعليمي فقط.`;

  // ── 5 providers — same as platform ─────────────────────────────────
  const providers: AIProvider[] = ["claude","gpt4","gemini","geminiPro","deepseek"];
  const settled = await Promise.allSettled(
    providers.map(async p => {
      const name = PROVIDER_CONFIGS[p].name;
      const icon = PROVIDER_CONFIGS[p].icon;
      if (!isProviderAvailable(p)) {
        return { provider:p, name, icon, signal:"ERROR", confidence:0, reasoning:"المزود غير متاح", entry:"—", sl:"—", tp:"—", risk:"—" };
      }
      try {
        const res = await callProvider(p, sys, ctx);
        const clean = res.content.replace(/```json\n?|```\n?/g,"").trim();
        const j = JSON.parse(clean.slice(clean.indexOf("{"), clean.lastIndexOf("}")+1));
        return { provider:p, name, icon,
          signal:j.signal, confidence:Math.min(100,Math.max(0,Number(j.confidence)||50)),
          reasoning:j.reasoning||"—", entry:j.entryZone||"—", sl:j.stopLoss||"—", tp:j.takeProfit||"—", risk:j.risk||"MEDIUM" };
      } catch (err: any) {
        console.error(`[TelegramBot] ${name} error:`, err.message);
        return { provider:p, name, icon, signal:"ERROR", confidence:0, reasoning:"", entry:"—", sl:"—", tp:"—", risk:"—" };
      }
    })
  );
  return settled.map(r => r.status==="fulfilled" ? r.value : { name:"—", icon:"⚠️", signal:"ERROR", confidence:0, reasoning:"", entry:"—", sl:"—", tp:"—", risk:"—" });
}

// ─── Message Builders ─────────────────────────────────────────────────
function sigIcon(s:"BUY"|"SELL"|"NEUTRAL") {
  return s==="BUY"?"🟢 شراء":s==="SELL"?"🔴 بيع":"🟡 محايد";
}

function buildQuickMsg(pair: string, tf: string, d: Awaited<ReturnType<typeof fetchMarket>>) {
  const p = PAIRS[pair];
  const buys  = d.strategies.filter(s=>s.signal==="BUY").length;
  const sells = d.strategies.filter(s=>s.signal==="SELL").length;
  const neutrals = d.strategies.length - buys - sells;
  const cons  = buys>sells?"🟢 شراء":sells>buys?"🔴 بيع":"🟡 محايد";
  return [
    `${p.flag} <b>${p.label}</b> | <code>${tf}</code>`,
    `💰 <b>${d.fmt(d.price)}</b>  <i>${d.datetime.slice(11,16)} UTC</i>`,
    ``,
    `<b>━━ 📊 المؤشرات ━━</b>`,
    `RSI <code>${d.RSI.toFixed(1)}</code> ${d.RSI<30?"🔴 ذروة بيع":d.RSI>70?"🟢 ذروة شراء":"⚪ محايد"}`,
    `MACD ${d.MACD.macd>d.MACD.signal?"✅ صاعد":"❌ هابط"} | BB ${d.price<d.BB.lower?"↓ أسفل":d.price>d.BB.upper?"↑ أعلى":"↔ داخل"} النطاق`,
    `SMA20 <code>${d.fmt(d.SMA20)}</code>${d.price>d.SMA20?" ✅":" ❌"}  SMA50 <code>${d.fmt(d.SMA50)}</code>${d.price>d.SMA50?" ✅":" ❌"}`,
    d.SMA200?`SMA200 <code>${d.fmt(d.SMA200)}</code>${d.price>d.SMA200?" ✅":" ❌"}`:`SMA200 —`,
    `ATR <code>${d.fmt(d.ATR)}</code>`,
    ``,
    `<b>━━ 🎯 الاستراتيجيات (${buys}🟢 ${sells}🔴 ${neutrals}🟡) ━━</b>`,
    ...d.strategies.map(s=>`${s.emoji} <b>${s.name}</b>: ${sigIcon(s.signal)}${s.signal!=="NEUTRAL"?` <code>${s.strength}%</code>`:""}\n   <i>${s.desc}</i>`),
    ``,
    `<b>━━ 🔍 الفلاتر ━━</b>`,
    ...d.filters.map(f=>`${f.passed?"✅":"⚠️"} ${f.emoji} <b>${f.name}</b>: <i>${f.desc}</i>`),
    ``,
    `┌──────────────────────────┐`,
    `│  التوافق: ${cons.padEnd(12)}│`,
    `└──────────────────────────┘`,
    ``,
    `<i>⚠️ للأغراض التعليمية فقط</i>`,
  ].join("\n");
}

function buildAIMsg(
  pair: string, tf: string,
  d: Awaited<ReturnType<typeof fetchMarket>>,
  aiResults: any[],
  isAutoSignal = false,
  news: NewsEvent[] = [],
) {
  const p = PAIRS[pair];
  const buys  = d.strategies.filter(s=>s.signal==="BUY").length;
  const sells = d.strategies.filter(s=>s.signal==="SELL").length;
  const valid = aiResults.filter(r=>r.signal!=="ERROR"&&r.signal!=="HOLD");
  const validAll = aiResults.filter(r=>r.signal!=="ERROR");
  const aiBuys  = valid.filter(r=>r.signal==="BUY").length;
  const aiSells = valid.filter(r=>r.signal==="SELL").length;
  const aiCons  = aiBuys>aiSells?"🟢 شراء":aiSells>aiBuys?"🔴 بيع":"🟡 انتظار";
  const avgConf = validAll.length ? Math.round(validAll.reduce((a:number,r:any)=>a+r.confidence,0)/validAll.length) : 0;
  const highImpactNews = news.filter(e=>e.impact==="High");

  return [
    isAutoSignal ? `🔔 <b>إشارة تلقائية!</b>` : "",
    `${p.flag} <b>تحليل AI كامل — ${p.label}</b> | <code>${tf}</code>`,
    `💰 <b>${d.fmt(d.price)}</b>  <i>${d.datetime.slice(11,16)} UTC</i>`,
    ``,
    `<b>━━ 📊 المؤشرات ━━</b>`,
    `RSI <code>${d.RSI.toFixed(1)}</code> ${d.RSI<30?"🔴 ذروة بيع":d.RSI>70?"🟢 ذروة شراء":"⚪"} | MACD ${d.MACD.macd>d.MACD.signal?"✅ صاعد":"❌ هابط"}`,
    `SMA20 ${d.price>d.SMA20?"✅":"❌"} | SMA50 ${d.price>d.SMA50?"✅":"❌"}${d.SMA200?" | SMA200 "+(d.price>d.SMA200?"✅":"❌"):""}`,
    `BB ${d.price<d.BB.lower?"↓ أسفل النطاق":d.price>d.BB.upper?"↑ أعلى النطاق":"↔ داخل النطاق"} | ATR <code>${d.fmt(d.ATR)}</code>`,
    ``,
    `<b>━━ 🎯 الاستراتيجيات (${buys}🟢 ${sells}🔴 ${d.strategies.length-buys-sells}🟡) ━━</b>`,
    ...d.strategies.map(s=>`${s.emoji} ${s.name}: ${sigIcon(s.signal)}${s.signal!=="NEUTRAL"?` <code>${s.strength}%</code>`:""}`),
    ``,
    `<b>━━ 🔍 الفلاتر ━━</b>`,
    ...d.filters.map(f=>`${f.passed?"✅":"⚠️"} ${f.emoji} ${f.name}: <i>${f.desc.split("—")[0].trim()}</i>`),
    // News warning
    ...(highImpactNews.length>0 ? [
      ``,
      `<b>━━ 📰 أخبار عالية التأثير ━━</b>`,
      ...highImpactNews.map(e=>`🔴 ${e.currency} — ${e.title}`),
      `<i>⚠️ تحذير: حذار من التداول قبل/بعد هذه الأخبار!</i>`,
    ] : news.length>0 ? [
      ``,
      `📰 أخبار متوسطة التأثير: ${news.map(e=>e.currency+"—"+e.title.slice(0,25)).join(" | ")}`,
    ] : []),
    ``,
    `<b>━━ 🤖 الذكاء الاصطناعي (5 نماذج) ━━</b>`,
    ...aiResults.map((r:any)=>r.signal==="ERROR"
      ? `${r.icon} <b>${r.name}</b>: ⚠️ غير متاح`
      : [
          `${r.icon} <b>${r.name}</b>: ${r.signal==="BUY"?"🟢 شراء":r.signal==="SELL"?"🔴 بيع":"🟡 انتظار"} <code>${r.confidence}%</code> | خطر: ${r.risk==="LOW"?"🟢 منخفض":r.risk==="HIGH"?"🔴 مرتفع":"🟡 متوسط"}`,
          `   💬 <i>${r.reasoning.slice(0,120)}${r.reasoning.length>120?"…":""}</i>`,
          `   🎯 دخول <code>${r.entry}</code> | SL <code>${r.sl}</code> | TP <code>${r.tp}</code>`,
        ].join("\n")
    ),
    ``,
    `┌────────────────────────────────┐`,
    `│  AI توافق: ${aiCons.padEnd(10)} ثقة: ${avgConf}%  │`,
    `└────────────────────────────────┘`,
    ``,
    `<i>⚠️ للأغراض التعليمية فقط — ليس توصية مالية</i>`,
  ].filter(l=>l!=="").join("\n");
}

// ─── Auto-Signal Scanner ──────────────────────────────────────────────
async function runAutoScan(bot: TelegramBot, ownerChatId: number, lastSignalTimeLocal: Map<string, number>) {
  if (!autoConfig.enabled) return;
  const { pairs, timeframes, minConsensus, minAIConfidence } = autoConfig;
  console.log(`[AutoScan] Scanning ${pairs.length} pairs × ${timeframes.length} timeframes`);

  for (const pair of pairs) {
    for (const tf of timeframes) {
      const key = `${pair}:${tf}`;
      const lastSent = lastSignalTimeLocal.get(key) || 0;
      if (Date.now() - lastSent < SIGNAL_COOLDOWN_MS) {
        console.log(`[AutoScan] ${key} skipped (cooldown)`);
        continue;
      }

      try {
        await new Promise(r => setTimeout(r, 1500)); // rate limit between requests
        const d = await fetchMarket(pair, TIMEFRAMES[tf]);
        const cons = calcConsensus(d.strategies);

        if (cons.direction === "NEUTRAL" || cons.pct < minConsensus) {
          console.log(`[AutoScan] ${key}: consensus ${cons.pct}% < ${minConsensus}% — skip`);
          continue;
        }

        console.log(`[AutoScan] ${key}: consensus ${cons.pct}% ≥ ${minConsensus}% — running AI + news...`);

        // Fetch news first, then run AI with it
        const news = await fetchEconomicNews(pair);
        const aiResults = await runAI(pair, tf, d, news);
        const valid = aiResults.filter((r:any) => r.signal !== "ERROR" && r.signal === cons.direction);
        const avgConf = valid.length
          ? Math.round(valid.reduce((a:number, r:any) => a + r.confidence, 0) / valid.length)
          : 0;

        if (avgConf < minAIConfidence || valid.length < 2) {
          console.log(`[AutoScan] ${key}: AI conf ${avgConf}% < ${minAIConfidence}% or only ${valid.length} models agree — skip`);
          continue;
        }

        // SEND SIGNAL!
        console.log(`[AutoScan] 🚨 Signal: ${pair} ${tf} ${cons.direction} — consensus ${cons.pct}%, AI conf ${avgConf}%`);
        lastSignalTimeLocal.set(key, Date.now());

        const msg = buildAIMsg(pair, tf, d, aiResults, true, news);
        await bot.sendMessage(ownerChatId, msg, {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [
                { text: "🔄 إعادة تحليل هذا الزوج", callback_data: `pair:${pair}` },
                { text: "🏠 القائمة الرئيسية",       callback_data: "back:pairs" },
              ],
            ],
          },
        });

      } catch (err: any) {
        console.error(`[AutoScan] ${key} error:`, err.message);
      }
    }
  }
}

function restartAutoScanner(bot: TelegramBot, ownerChatId: number, lastSignalTimeLocal: Map<string, number>) {
  if (autoScanTimer) {
    clearInterval(autoScanTimer);
    autoScanTimer = null;
  }
  if (!autoConfig.enabled) return;
  const ms = autoConfig.intervalMinutes * 60 * 1000;
  console.log(`[AutoScan] Started — interval ${autoConfig.intervalMinutes}min, pairs: ${autoConfig.pairs.join(",")}, TFs: ${autoConfig.timeframes.join(",")}`);
  // Run once immediately
  setTimeout(() => runAutoScan(bot, ownerChatId, lastSignalTimeLocal), 2000);
  autoScanTimer = setInterval(() => runAutoScan(bot, ownerChatId, lastSignalTimeLocal), ms);
}

// ─── Convergence Config ──────────────────────────────────────────────
interface ConvergenceConfig {
  enabled: boolean;
  intervalMinutes: number;
}
let convergenceConfig: ConvergenceConfig = { enabled: true, intervalMinutes: 5 };
let convergenceTimer: NodeJS.Timeout | null = null;
const convergenceCooldown = new Map<string, number>();
const CONVERGENCE_COOLDOWN_MS = 60 * 60 * 1000;

export interface ConvergenceSignal {
  pair: string;
  flag: string;
  direction: "BUY" | "SELL";
  avgPct: number;
  aiConfidence: number;
  aiModels: number;
  totalModels: number;
  price: string;
  timestamp: string;
  tfDetails: { tf: string; direction: string; pct: number; buys: number; sells: number }[];
  aiDetails: { name: string; icon: string; signal: string; confidence: number; entry: string; sl: string; tp: string; reasoning: string }[];
  newsWarnings: string[];
}

const convergenceSignals: ConvergenceSignal[] = [];
const MAX_CONVERGENCE_SIGNALS = 50;

export function getConvergenceConfig() { return { ...convergenceConfig }; }
let _botRef: TelegramBot | null = null;
let _ownerRef: number = 0;
export function setConvergenceConfig(patch: Partial<ConvergenceConfig>) {
  if (patch.enabled !== undefined) convergenceConfig.enabled = patch.enabled;
  if (patch.intervalMinutes !== undefined) convergenceConfig.intervalMinutes = patch.intervalMinutes;
  if (_botRef && _ownerRef) restartConvergenceScanner(_botRef, _ownerRef);
}
export function getConvergenceSignals() { return [...convergenceSignals]; }
export function triggerConvergenceScan() { return _triggerConvergenceScanRef; }
export async function sendTestConvergenceSignal() {
  if (!_botRef || !_ownerRef) return "Bot not initialized";
  const testSignal: ConvergenceSignal = {
    pair: "XAUUSD", flag: "🥇", direction: "BUY",
    avgPct: 82, aiConfidence: 78, aiModels: 2, totalModels: 3,
    price: "3,245.50", timestamp: new Date().toISOString(),
    tfDetails: [
      { tf: "1m", direction: "BUY", pct: 78, buys: 6, sells: 2 },
      { tf: "5m", direction: "BUY", pct: 85, buys: 7, sells: 1 },
      { tf: "15m", direction: "BUY", pct: 83, buys: 7, sells: 1 },
    ],
    aiDetails: [
      { name: "GPT-4o", icon: "🧠", signal: "BUY", confidence: 82, entry: "3,244.00", sl: "3,238.00", tp: "3,260.00", reasoning: "اختراق مقاومة + RSI صاعد + MACD إيجابي" },
      { name: "Claude", icon: "🤖", signal: "BUY", confidence: 75, entry: "3,245.00", sl: "3,239.00", tp: "3,258.00", reasoning: "زخم صعودي قوي مدعوم بالمتوسطات" },
      { name: "Gemini", icon: "💎", signal: "SELL", confidence: 45, entry: "", sl: "", tp: "", reasoning: "إشارة غير مؤكدة" },
    ],
    newsWarnings: [],
  };
  convergenceSignals.unshift(testSignal);
  if (convergenceSignals.length > MAX_CONVERGENCE_SIGNALS) convergenceSignals.length = MAX_CONVERGENCE_SIGNALS;

  const tfDetails = testSignal.tfDetails.map(t =>
    `<code>${t.tf.padEnd(4)}</code> ${t.direction === "BUY" ? "🟢" : "🔴"} ${t.direction} <code>${t.pct}%</code> (${t.buys}🟢 ${t.sells}🔴)`
  ).join("\n");
  const aiDetails = testSignal.aiDetails.map((r: any) => {
    if (r.signal === "ERROR") return `${r.icon} <b>${r.name}</b>: ⚠️ غير متاح`;
    return [
      `${r.icon} <b>${r.name}</b>: ${r.signal === "BUY" ? "🟢 شراء" : r.signal === "SELL" ? "🔴 بيع" : "🟡 انتظار"} <code>${r.confidence}%</code>`,
      `   🎯 دخول <code>${r.entry}</code> | SL <code>${r.sl}</code> | TP <code>${r.tp}</code>`,
      `   💬 <i>${r.reasoning}</i>`,
    ].join("\n");
  }).join("\n");

  const msg = [
    `🎯🎯🎯 <b>تطابق كامل!</b> 🎯🎯🎯`,
    ``,
    `🥇 <b>XAUUSD — الذهب</b> — 🟢 شراء قوية`,
    `💰 السعر: <b>3,245.50</b>`,
    ``,
    `<b>━━ 📊 تطابق 3 فريمات ━━</b>`,
    tfDetails,
    `📊 متوسط التوافق: <b>82%</b>`,
    ``,
    `<b>━━ 🤖 تأكيد AI (2/3 نموذج) ━━</b>`,
    aiDetails,
    ``,
    `┌──────────────────────────────────┐`,
    `│  🎯 التطابق: 🟢 شراء  ثقة AI: 78%  │`,
    `│  3/3 فريمات متطابقة             │`,
    `└──────────────────────────────────┘`,
    ``,
    `<i>⚠️ إشارة اختبار — للتحقق من عمل النظام</i>`,
  ].join("\n");

  await _botRef.sendMessage(_ownerRef, msg, { parse_mode: "HTML" });
  console.log("[Test] ✅ Test convergence signal sent to Telegram");
  return "sent";
}

let _triggerConvergenceScanRef: (() => Promise<void>) | null = null;

const CONVERGENCE_TFS: { key: string; cfg: TfConfig }[] = [
  { key: "1m",  cfg: TIMEFRAMES["1m"]  },
  { key: "5m",  cfg: TIMEFRAMES["5m"]  },
  { key: "15m", cfg: TIMEFRAMES["15m"] },
];

async function runConvergenceScan(bot: TelegramBot, ownerChatId: number) {
  if (!convergenceConfig.enabled) return;
  const allPairs = Object.keys(PAIRS);
  console.log(`[Convergence] Scanning ${allPairs.length} pairs × 3 timeframes (1m, 5m, 15m)...`);
  try {

  for (const pair of allPairs) {
    const coolKey = `conv:${pair}`;
    const lastSent = convergenceCooldown.get(coolKey) || 0;
    if (Date.now() - lastSent < CONVERGENCE_COOLDOWN_MS) continue;

    try {
      const results: { tf: string; direction: "BUY"|"SELL"|"NEUTRAL"; pct: number; data: any }[] = [];

      for (const { key, cfg } of CONVERGENCE_TFS) {
        await new Promise(r => setTimeout(r, 8500));
        const d = await fetchMarket(pair, cfg);
        const cons = calcConsensus(d.strategies);
        results.push({ tf: key, direction: cons.direction, pct: cons.pct, data: d });
      }

      const dirs = results.map(r => r.direction);
      if (dirs.includes("NEUTRAL")) {
        console.log(`[Convergence] ${pair}: has NEUTRAL tf — skip`);
        continue;
      }

      const allBuy  = dirs.every(d => d === "BUY");
      const allSell = dirs.every(d => d === "SELL");
      if (!allBuy && !allSell) {
        console.log(`[Convergence] ${pair}: no agreement (${dirs.join(",")}) — skip`);
        continue;
      }

      const convergenceDir = allBuy ? "BUY" : "SELL";
      const avgPct = Math.round(results.reduce((a, r) => a + r.pct, 0) / results.length);

      if (avgPct < 60) {
        console.log(`[Convergence] ${pair}: avg consensus ${avgPct}% too low — skip`);
        continue;
      }

      console.log(`[Convergence] 🎯 ${pair} MATCH! ${convergenceDir} across all 3 TFs — running AI...`);

      const news = await fetchEconomicNews(pair);
      const aiResults = await runAI(pair, "1m,5m,15m", results[2].data, news);
      const validAI = aiResults.filter((r: any) => r.signal !== "ERROR" && r.signal === convergenceDir);
      const avgConf = validAI.length
        ? Math.round(validAI.reduce((a: number, r: any) => a + r.confidence, 0) / validAI.length)
        : 0;

      if (validAI.length < 2 || avgConf < 60) {
        console.log(`[Convergence] ${pair}: AI doesn't confirm (${validAI.length} models, ${avgConf}% conf) — skip`);
        continue;
      }

      convergenceCooldown.set(coolKey, Date.now());

      const p = PAIRS[pair];
      const d15 = results[2].data;
      const filtersInfo = d15.filters.map((f: any) => `${f.passed?"✅":"⚠️"} ${f.emoji} ${f.name}`).join("\n");

      const tfDetailsArr = results.map(r => {
        const buys = r.data.strategies.filter((s: Sig) => s.signal === "BUY").length;
        const sells = r.data.strategies.filter((s: Sig) => s.signal === "SELL").length;
        return { tf: r.tf, direction: r.direction, pct: r.pct, buys, sells };
      });
      const tfDetails = tfDetailsArr.map(t =>
        `<code>${t.tf.padEnd(4)}</code> ${t.direction === "BUY" ? "🟢" : "🔴"} ${t.direction} <code>${t.pct}%</code> (${t.buys}🟢 ${t.sells}🔴)`
      ).join("\n");

      const aiDetailsArr = aiResults.map((r: any) => ({
        name: r.name || r.provider, icon: r.icon || "",
        signal: r.signal || "ERROR", confidence: r.confidence || 0,
        entry: r.entry || "", sl: r.sl || "", tp: r.tp || "",
        reasoning: r.reasoning || "",
      }));
      const aiDetails = aiResults.map((r: any) => {
        if (r.signal === "ERROR") return `${r.icon} <b>${r.name}</b>: ⚠️ غير متاح`;
        return [
          `${r.icon} <b>${r.name}</b>: ${r.signal === "BUY" ? "🟢 شراء" : r.signal === "SELL" ? "🔴 بيع" : "🟡 انتظار"} <code>${r.confidence}%</code>`,
          `   🎯 دخول <code>${r.entry}</code> | SL <code>${r.sl}</code> | TP <code>${r.tp}</code>`,
          `   💬 <i>${r.reasoning.slice(0, 100)}${r.reasoning.length > 100 ? "…" : ""}</i>`,
        ].join("\n");
      }).join("\n");

      const highImpactNews = news.filter(e => e.impact === "High");

      const convSignal: ConvergenceSignal = {
        pair, flag: p.flag, direction: convergenceDir as "BUY"|"SELL",
        avgPct, aiConfidence: avgConf, aiModels: validAI.length, totalModels: aiResults.length,
        price: d15.fmt(d15.price), timestamp: new Date().toISOString(),
        tfDetails: tfDetailsArr, aiDetails: aiDetailsArr,
        newsWarnings: highImpactNews.map(e => `${e.currency} — ${e.title}`),
      };
      convergenceSignals.unshift(convSignal);
      if (convergenceSignals.length > MAX_CONVERGENCE_SIGNALS) convergenceSignals.length = MAX_CONVERGENCE_SIGNALS;

      const msg = [
        `🎯🎯🎯 <b>تطابق كامل!</b> 🎯🎯🎯`,
        ``,
        `${p.flag} <b>${p.label}</b> — ${convergenceDir === "BUY" ? "🟢 شراء قوية" : "🔴 بيع قوي"}`,
        `💰 السعر: <b>${d15.fmt(d15.price)}</b>  <i>${d15.datetime.slice(11, 16)} UTC</i>`,
        ``,
        `<b>━━ 📊 تطابق 3 فريمات ━━</b>`,
        tfDetails,
        `📊 متوسط التوافق: <b>${avgPct}%</b>`,
        ``,
        `<b>━━ 📈 المؤشرات (15م) ━━</b>`,
        `RSI <code>${d15.RSI.toFixed(1)}</code> ${d15.RSI < 30 ? "🔴 ذروة بيع" : d15.RSI > 70 ? "🟢 ذروة شراء" : "⚪"} | MACD ${d15.MACD.macd > d15.MACD.signal ? "✅ صاعد" : "❌ هابط"}`,
        `SMA20 ${d15.price > d15.SMA20 ? "✅" : "❌"} | SMA50 ${d15.price > d15.SMA50 ? "✅" : "❌"}${d15.SMA200 ? " | SMA200 " + (d15.price > d15.SMA200 ? "✅" : "❌") : ""}`,
        `BB ${d15.price < d15.BB.lower ? "↓ أسفل" : d15.price > d15.BB.upper ? "↑ أعلى" : "↔ داخل"} | ATR <code>${d15.fmt(d15.ATR)}</code>`,
        ``,
        `<b>━━ 🎯 الاستراتيجيات (15م) ━━</b>`,
        ...d15.strategies.map((s: Sig) => `${s.emoji} ${s.name}: ${s.signal === "BUY" ? "🟢" : s.signal === "SELL" ? "🔴" : "🟡"} ${s.signal !== "NEUTRAL" ? `<code>${s.strength}%</code>` : ""}`),
        ``,
        `<b>━━ 🔍 الفلاتر ━━</b>`,
        filtersInfo,
        ...(highImpactNews.length > 0 ? [
          ``,
          `<b>━━ 📰 تحذير أخبار ━━</b>`,
          ...highImpactNews.map(e => `🔴 ${e.currency} — ${e.title}`),
          `<i>⚠️ احذر من التداول!</i>`,
        ] : []),
        ``,
        `<b>━━ 🤖 تأكيد AI (${validAI.length}/${aiResults.length} نموذج) ━━</b>`,
        aiDetails,
        ``,
        `┌──────────────────────────────────┐`,
        `│  🎯 التطابق: ${convergenceDir === "BUY" ? "🟢 شراء" : "🔴 بيع"}  ثقة AI: ${avgConf}%  │`,
        `│  3/3 فريمات متطابقة             │`,
        `└──────────────────────────────────┘`,
        ``,
        `<i>⚠️ للأغراض التعليمية فقط — ليس توصية مالية</i>`,
      ].join("\n");

      await bot.sendMessage(ownerChatId, msg, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "🔄 إعادة تحليل", callback_data: `pair:${pair}` },
              { text: "🏠 القائمة", callback_data: "back:pairs" },
            ],
          ],
        },
      });

    } catch (err: any) {
      console.error(`[Convergence] ${pair} error:`, err.message);
    }
  }
  } catch (outerErr: any) {
    console.error(`[Convergence] Fatal scan error:`, outerErr.message || outerErr);
  }
}

function restartConvergenceScanner(bot: TelegramBot, ownerChatId: number) {
  if (convergenceTimer) { clearInterval(convergenceTimer); convergenceTimer = null; }
  _triggerConvergenceScanRef = async () => {
    const prev = convergenceConfig.enabled;
    convergenceConfig.enabled = true;
    await runConvergenceScan(bot, ownerChatId);
    convergenceConfig.enabled = prev;
  };
  if (!convergenceConfig.enabled) return;
  const ms = convergenceConfig.intervalMinutes * 60 * 1000;
  console.log(`[Convergence] Started — interval ${convergenceConfig.intervalMinutes}min, all ${Object.keys(PAIRS).length} pairs`);
  setTimeout(() => runConvergenceScan(bot, ownerChatId).catch(e => console.error("[Convergence] scan error:", e.message)), 3000);
  convergenceTimer = setInterval(() => runConvergenceScan(bot, ownerChatId).catch(e => console.error("[Convergence] scan error:", e.message)), ms);
}

// ─── Bot Initialization ───────────────────────────────────────────────
/**
 * Start the bot.
 * - webhookUrl supplied  → webhook mode (production): no polling, registers webhook with Telegram
 * - webhookUrl undefined → polling mode (dev / FORCE_BOT=true)
 * Returns the bot instance so callers can attach Express webhook route.
 */
export function startTelegramBot(webhookUrl?: string, tokenOverride?: string, botRole: "trading" | "bridge" = "bridge"): TelegramBot | undefined {
  const token = tokenOverride || BOT_TOKEN;
  if (!token)    { console.log("[TelegramBot] Bot token not set — disabled"); return; }
  if (!OWNER_ID) { console.log("[TelegramBot] TELEGRAM_OWNER_CHAT_ID not set — disabled"); return; }

  const useWebhook = !!webhookUrl;
  const botLabel = botRole === "trading" ? "[Bot1-Trading]" : "[Bot2-Bridge]";

  const bot = new TelegramBot(token, {
    polling: !useWebhook ? { interval: 3000, autoStart: true, params: { timeout: 10 } } : false,
  });

  if (!useWebhook) {
    fetch(`https://api.telegram.org/bot${token}/deleteWebhook?drop_pending_updates=true`, { method: "POST" })
      .then(r => r.json())
      .then((d: any) => console.log(`${botLabel} deleteWebhook:`, d.description || "ok"))
      .catch(() => {});
  }
  // Override polling error handler to include bot role in log
  (bot as any).on("polling_error", (err: any) => {
    const msg = err?.message || String(err);
    if (msg.includes("409 Conflict")) {
      console.warn(`${botLabel} 409 Conflict — another instance may be running with this token`);
    } else if (!msg.includes("EFATAL")) {
      console.warn(`${botLabel} Polling error:`, msg.slice(0, 120));
    }
  });
  const ownerChatId = parseInt(OWNER_ID, 10);
  const isOwner = (chatId: number) => chatId === ownerChatId;

  // Per-instance session state (each bot has its own, no cross-bot contamination)
  const sessions = new Map<number, Session>();
  function getSession(chatId: number): Session {
    if (!sessions.has(chatId)) sessions.set(chatId, {});
    return sessions.get(chatId)!;
  }
  const lastSignalTimeLocal = new Map<string, number>();

  // ── Safe send helper — falls back to plain text if Markdown parse fails ──
  function stripMd(text: string): string {
    // Remove Markdown formatting characters that Telegram can't parse
    return text.replace(/[*_`\[\]]/g, "");
  }

  async function safeSend(
    chatId: number,
    text: string,
    opts: TelegramBot.SendMessageOptions = {}
  ): Promise<void> {
    const truncated = text.substring(0, 4096);
    try {
      await bot.sendMessage(chatId, truncated, { parse_mode: "Markdown", ...opts });
    } catch (e: any) {
      if (e?.message?.includes("can't parse entities") || e?.response?.body?.description?.includes("can't parse entities")) {
        // Retry as plain text, stripping markdown symbols
        const plain = stripMd(truncated);
        await bot.sendMessage(chatId, plain, { ...opts, parse_mode: undefined });
      } else {
        throw e;
      }
    }
  }

  // ── Send menus ──────────────────────────────────────────────────
  async function sendPairsMenu(chatId: number, editing?: number) {
    const status = autoConfig.enabled
      ? `🤖 الإشارات التلقائية: <b>✅ مفعّلة</b>\n📋 ${autoConfig.pairs.join(", ")} | كل ${autoConfig.intervalMinutes} دقيقة\n`
      : `🤖 الإشارات التلقائية: <b>❌ معطّلة</b>\n`;
    const text = `🏦 <b>HAYO Trading Bot</b>\n\n${status}\nاختر الزوج الذي تريد تحليله:`;
    if (editing) {
      await bot.editMessageText(text, { chat_id:chatId, message_id:editing, parse_mode:"HTML", reply_markup:pairsKeyboard() });
    } else {
      await bot.sendMessage(chatId, text, { parse_mode:"HTML", reply_markup:pairsKeyboard() });
    }
  }

  async function sendTfMenu(chatId: number, editing?: number) {
    const session = getSession(chatId);
    const p = PAIRS[session.pair!];
    const text = `${p.flag} <b>${p.label}</b> — اختر الإطار الزمني:`;
    if (editing) {
      await bot.editMessageText(text, { chat_id:chatId, message_id:editing, parse_mode:"HTML", reply_markup:timeframesKeyboard() });
    } else {
      await bot.sendMessage(chatId, text, { parse_mode:"HTML", reply_markup:timeframesKeyboard() });
    }
  }

  async function sendAnalysisMenu(chatId: number, editing?: number) {
    const session = getSession(chatId);
    const p = PAIRS[session.pair!];
    const text = `${p.flag} <b>${p.label}</b> | <code>${session.tf}</code>\n\nاختر نوع التحليل:`;
    if (editing) {
      await bot.editMessageText(text, { chat_id:chatId, message_id:editing, parse_mode:"HTML", reply_markup:analysisTypeKeyboard() });
    } else {
      await bot.sendMessage(chatId, text, { parse_mode:"HTML", reply_markup:analysisTypeKeyboard() });
    }
  }

  async function sendAutoMenu(chatId: number, editing?: number) {
    const text = [
      `⚙️ <b>إعدادات الإشارات التلقائية</b>`,
      ``,
      `الحالة: ${autoConfig.enabled ? "✅ <b>مفعّلة</b>" : "❌ <b>معطّلة</b>"}`,
      `الأزواج: <code>${autoConfig.pairs.join(", ")||"لا يوجد"}</code>`,
      `الإطارات: <code>${autoConfig.timeframes.join(", ")||"لا يوجد"}</code>`,
      `فترة الفحص: كل <code>${autoConfig.intervalMinutes}</code> دقيقة`,
      `الحد الأدنى للتوافق: <code>${autoConfig.minConsensus}%</code>`,
      `ثقة AI الأدنى: <code>${autoConfig.minAIConfidence}%</code>`,
      ``,
      `اضغط ✅ على خيار لتفعيله أو إلغائه:`,
    ].join("\n");
    if (editing) {
      await bot.editMessageText(text, { chat_id:chatId, message_id:editing, parse_mode:"HTML", reply_markup:autoMenuKeyboard() });
    } else {
      await bot.sendMessage(chatId, text, { parse_mode:"HTML", reply_markup:autoMenuKeyboard() });
    }
  }

  // ── /start ─────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════
  // HAYO Bridge Bot — Full Platform Control from Telegram
  // ═══════════════════════════════════════════════════════════════

  // Main Menu Keyboard
  function mainMenuKeyboard(): TelegramBot.InlineKeyboardMarkup {
    return {
      inline_keyboard: [
        [
          { text: "💬 دردشة AI", callback_data: "bridge:chat" },
          { text: "🤖 وكيل الكود", callback_data: "bridge:agent" },
        ],
        [
          { text: "📱 منشئ تطبيقات", callback_data: "bridge:appbuilder" },
          { text: "🔬 هندسة عكسية", callback_data: "bridge:reverse" },
        ],
        [
          { text: "📄 أعمال مكتبية", callback_data: "bridge:office" },
          { text: "📊 دراسات", callback_data: "bridge:studies" },
        ],
        [
          { text: "🪄 مصنع برومبت", callback_data: "bridge:prompt" },
          { text: "🗺️ خرائط ذهنية", callback_data: "bridge:mindmap" },
        ],
        [
          { text: "⚙️ EA Factory", callback_data: "bridge:ea" },
          { text: "🎨 توليد صور", callback_data: "bridge:image" },
        ],
        [
          { text: "📈 تحليل أسواق", callback_data: "pair_menu" },
          { text: "🔍 OSINT", callback_data: "bridge:osint" },
        ],
        [
          { text: "🚀 منفّذ ذكي (صيانة)", callback_data: "bridge:executive" },
        ],
        [
          { text: `📡 إشارات تلقائية ${autoConfig.enabled ? "✅" : "❌"}`, callback_data: "auto:menu" },
          { text: `🎯 التطابق ${convergenceConfig.enabled ? "✅" : "❌"}`, callback_data: "conv:menu" },
        ],
      ],
    };
  }

  // Session extended for bridge
  interface BridgeSession {
    mode?: "chat" | "agent" | "appbuilder" | "office" | "studies" | "prompt" | "image" | "ea" | "maintenance" | "executive" | "osint" | "mindmap" | "reverse";
    subStep?: string;
    data?: Record<string, any>;
  }
  const bridgeSessions = new Map<number, BridgeSession>();
  function getBridgeSession(chatId: number): BridgeSession {
    if (!bridgeSessions.has(chatId)) bridgeSessions.set(chatId, {});
    return bridgeSessions.get(chatId)!;
  }

  bot.onText(/\/start/, async (msg) => {
    try {
      if (!isOwner(msg.chat.id)) return;
      sessions.set(msg.chat.id, {});
      bridgeSessions.set(msg.chat.id, {});
      if (botRole === "trading") {
        await bot.sendMessage(msg.chat.id,
          `📈 *HAYO Trading Bot*\n\n` +
          `بوت إشارات التداول الذكي 🤖\n\n` +
          `الأوامر المتاحة:\n` +
          `• /scan — تحليل سوق فوري\n` +
          `• /auto — إعدادات الإشارات التلقائية\n` +
          `• /signals — آخر الإشارات\n\n` +
          `اختر زوجاً للتحليل:`,
          { parse_mode: "Markdown", reply_markup: pairsKeyboard() }
        );
      } else {
        await bot.sendMessage(msg.chat.id,
          `🚀 *HAYO AI Bridge Bot*\n\n` +
          `مرحباً بك يا مالك المنصة 👑\n` +
          `تحكم بكامل منصة HAYO AI من هنا:\n\n` +
          `اختر القسم المطلوب:`,
          { parse_mode: "Markdown", reply_markup: mainMenuKeyboard() }
        );
      }
    } catch (e: any) { console.warn("[TelegramBot] /start error:", e?.message); }
  });

  bot.onText(/\/menu/, async (msg) => {
    try {
      if (!isOwner(msg.chat.id)) return;
      bridgeSessions.set(msg.chat.id, {});
      if (botRole === "trading") {
        await bot.sendMessage(msg.chat.id, "📈 *اختر زوجاً للتحليل:*", { parse_mode: "Markdown", reply_markup: pairsKeyboard() });
      } else {
        await bot.sendMessage(msg.chat.id, "🏠 *القائمة الرئيسية*\n\nاختر القسم:", { parse_mode: "Markdown", reply_markup: mainMenuKeyboard() });
      }
    } catch (e: any) { console.warn("[TelegramBot] /menu error:", e?.message); }
  });

  // ── Callback Query ─────────────────────────────────────────────
  bot.on("callback_query", async (query) => {
    // Always acknowledge first — silently ignore if expired
    try { await bot.answerCallbackQuery(query.id); } catch {}

    try {
    if (!query.message || !isOwner(query.message.chat.id)) return;

    const chatId  = query.message.chat.id;
    const msgId   = query.message.message_id;
    const data    = query.data ?? "";
    const session = getSession(chatId);
    const bridgeSession = getBridgeSession(chatId);

    // Helper to edit the current message (prevents double-message on button press)
    async function editNav(text: string, opts: Partial<TelegramBot.EditMessageTextOptions> = {}) {
      try {
        await bot.editMessageText(text, { chat_id: chatId, message_id: msgId, parse_mode: "Markdown", ...opts });
      } catch {
        await bot.sendMessage(chatId, text, { parse_mode: "Markdown", ...opts as any });
      }
    }

    // ═══ Bridge Menu Handlers ═══════════════════════════════════
    if (data === "pair_menu") {
      session.pair = undefined; session.tf = undefined;
      await sendPairsMenu(chatId, msgId);
      return;
    }

    if (data === "bridge:main") {
      bridgeSessions.set(chatId, {});
      await editNav("🏠 *القائمة الرئيسية*\n\nاختر القسم المطلوب:", { reply_markup: mainMenuKeyboard() });
      return;
    }

    // ── Chat AI ──
    if (data === "bridge:chat") {
      bridgeSession.mode = "chat"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "💬 *دردشة AI*\n\nاكتب رسالتك وسيرد عليك أقوى نموذج AI:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Code Agent ──
    if (data === "bridge:agent") {
      bridgeSession.mode = "agent"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "🤖 *وكيل الكود*\n\nاكتب ما تريد برمجته وسينفّذ الوكيل المهمة:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── App Builder ──
    if (data === "bridge:appbuilder") {
      bridgeSession.mode = "appbuilder"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId,
        "📱 *منشئ التطبيقات*\n\n" +
        "اكتب وصف التطبيق المطلوب بالتفصيل.\n\n" +
        "🤖 سأبني لك APK جاهز للتحميل تلقائياً!",
        { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Reverse Engineering ──
    if (data === "bridge:reverse") {
      bridgeSession.mode = "reverse"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId,
        "🔬 *الهندسة العكسية*\n\n" +
        "الصق الكود المراد تحليله أو اكتب وصف ما تريد فهمه.\n\n" +
        "🧠 Claude Opus + Gemini Pro سيحللانه معاً:",
        { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Office Suite ──
    if (data === "bridge:office") {
      bridgeSession.mode = "office"; bridgeSession.subStep = "choose";
      await editNav("📄 *الأعمال المكتبية*\n\nاختر نوع الملف:", {
        reply_markup: { inline_keyboard: [
          [{ text: "📊 عرض تقديمي", callback_data: "office:pptx" }, { text: "📝 تقرير Word", callback_data: "office:word" }],
          [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
        ]},
      });
      return;
    }
    if (data === "office:pptx") {
      bridgeSession.subStep = "pptx";
      await bot.sendMessage(chatId, "📊 اكتب موضوع العرض التقديمي:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }
    if (data === "office:word") {
      bridgeSession.subStep = "word";
      await bot.sendMessage(chatId, "📝 اكتب موضوع التقرير:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Studies ──
    if (data === "bridge:studies") {
      bridgeSession.mode = "studies"; bridgeSession.subStep = "choose";
      await editNav("📊 *دراسات واستشارات*\n\nاختر التصنيف:", {
        reply_markup: { inline_keyboard: [
          [{ text: "🏗️ هندسة", callback_data: "study:engineering" }, { text: "💰 تجارة", callback_data: "study:commerce" }],
          [{ text: "📊 جدوى", callback_data: "study:investment" }, { text: "🏥 طب", callback_data: "study:medical" }],
          [{ text: "💻 تقنية", callback_data: "study:tech" }, { text: "🌾 زراعة", callback_data: "study:agriculture" }],
          [{ text: "🔬 عام", callback_data: "study:general" }],
          [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
        ]},
      });
      return;
    }
    if (data.startsWith("study:")) {
      bridgeSession.subStep = "study_input";
      bridgeSession.data = { category: data.split(":")[1] };
      await bot.sendMessage(chatId, "✍️ اكتب وصف مشروعك بالتفصيل:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Prompt Factory ──
    if (data === "bridge:prompt") {
      bridgeSession.mode = "prompt"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "🪄 *مصنع البرومبت*\n\nاكتب فكرتك وسأحولها لبرومبت احترافي:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Mind Map ──
    if (data === "bridge:mindmap") {
      bridgeSession.mode = "mindmap"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "🗺️ *خرائط ذهنية*\n\nاكتب الموضوع أو المفهوم لإنشاء خريطة ذهنية منظمة:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── OSINT ──
    if (data === "bridge:osint") {
      bridgeSession.mode = "osint"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "🔍 *OSINT — استخبارات المصادر المفتوحة*\n\nاكتب اسم شخص، شركة، نطاق، أو أي هدف للبحث والتحليل:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Image Generation ──
    if (data === "bridge:image") {
      bridgeSession.mode = "image"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "🎨 *توليد صور AI*\n\nاكتب وصف الصورة المطلوبة:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── EA Factory ──
    if (data === "bridge:ea") {
      bridgeSession.mode = "ea"; bridgeSession.subStep = "choose";
      await editNav("⚙️ *EA Factory — مصنع الخبراء*\n\nاختر نوع الاستراتيجية:", {
        reply_markup: { inline_keyboard: [
          [{ text: "📈 تقاطع المتوسطات (MA Crossover)", callback_data: "ea:ma_cross" }],
          [{ text: "📊 RSI العكسي (Reversal)", callback_data: "ea:rsi_reversal" }],
          [{ text: "💥 اختراق النطاق (Breakout)", callback_data: "ea:breakout" }],
          [{ text: "🎯 بولنجر باند (Bollinger)", callback_data: "ea:bollinger" }],
          [{ text: "✍️ استراتيجية مخصصة", callback_data: "ea:custom" }],
          [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
        ]},
      });
      return;
    }
    if (data.startsWith("ea:") && ["ea:ma_cross","ea:rsi_reversal","ea:breakout","ea:bollinger","ea:custom"].includes(data)) {
      const eaNames: Record<string,string> = { ma_cross:"تقاطع المتوسطات", rsi_reversal:"RSI العكسي", breakout:"اختراق النطاق", bollinger:"بولنجر باند", custom:"مخصصة" };
      bridgeSession.data = { eaType: data.split(":")[1] };
      bridgeSession.subStep = "ea_params";
      await bot.sendMessage(chatId,
        `⚙️ *EA — ${eaNames[data.split(":")[1]]}*\n\n` +
        `صِف معاملات الاستراتيجية:\n` +
        `• الزوج والإطار الزمني\n• معاملات الإدخال (فترات، عتبات)\n• وقف الخسارة وهدف الربح\n\n` +
        `مثال: _EURUSD، H1، MA20 و MA50، SL=20 نقطة، TP=40 نقطة_`,
        { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } }
      );
      return;
    }

    // ── Executive Agent (Maintenance++) ──
    if (data === "bridge:executive") {
      bridgeSession.mode = "executive";
      await editNav("🚀 *المنفّذ التنفيذي الذكي*\n\nنظام صيانة وإصلاح ذاتي متكامل.\nاختر العملية:", {
        reply_markup: { inline_keyboard: [
          [{ text: "🔍 فحص شامل + تقرير", callback_data: "maint:scan" }],
          [{ text: "🟢 حالة النظام", callback_data: "maint:health" }],
          [{ text: "🧠 تشخيص AI ذكي", callback_data: "maint:diagnose" }],
          [{ text: "🚀 تنفيذ ذكي شامل (Auto-Fix)", callback_data: "exec:auto" }],
          [{ text: "🔧 إصلاح صفحة بعينها", callback_data: "exec:fix_page" }],
          [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
        ]},
      });
      return;
    }
    if (data === "exec:auto") {
      await bot.sendMessage(chatId, "🚀 *تشغيل المنفّذ التنفيذي الشامل...*\n\n📊 المراحل:\n1️⃣ فحص سريع للمشروع\n2️⃣ تشخيص AI للأخطاء\n3️⃣ توليد وتطبيق الإصلاحات\n\n⏳ هذا قد يستغرق 1-2 دقيقة...", { parse_mode: "Markdown" });
      (async () => {
        try {
          const { autoExecute } = await import("../hayo/services/maintenance.js");
          const result = await autoExecute(process.cwd());
          let reply = `🚀 *نتائج المنفّذ التنفيذي:*\n\n`;
          reply += `📊 درجة الفحص: *${result.scan?.score || "N/A"}/100*\n`;
          if (result.diagnosis?.report) {
            reply += `\n🧠 *التشخيص:*\n${result.diagnosis.report.substring(0, 800)}\n`;
          }
          if (result.fixes && result.fixes.length > 0) {
            reply += `\n🔧 *تم تطبيق ${result.fixes.length} إصلاح:*\n`;
            result.fixes.slice(0, 5).forEach((f: any) => {
              reply += `\n✅ ${f.file || f.description?.substring(0, 60)}`;
            });
          } else {
            reply += `\n✅ لا إصلاحات ضرورية — المشروع سليم`;
          }
          await safeSend(chatId, reply.substring(0, 4000), { reply_markup: { inline_keyboard: [[{ text: "🔄 إعادة التنفيذ", callback_data: "exec:auto" }, { text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
        } catch (e: any) {
          await bot.sendMessage(chatId, `❌ خطأ في التنفيذ الذكي: ${e.message?.substring(0, 300)}`);
        }
      })();
      return;
    }
    if (data === "exec:fix_page") {
      bridgeSession.mode = "executive"; bridgeSession.subStep = "exec_input";
      await bot.sendMessage(chatId, "🔧 *إصلاح موجّه*\n\nاكتب وصف المشكلة أو اسم الصفحة/الملف المراد إصلاحه:\n\nمثال: _صفحة TradingAnalysis لا تعمل_ أو _خطأ في providers.ts_", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Maintenance (legacy) ──
    if (data === "bridge:maintenance") {
      bridgeSession.mode = "maintenance";
      await editNav("🔧 *صيانة النظام*\n\nاختر العملية:", {
        reply_markup: { inline_keyboard: [
          [{ text: "🟢 حالة النظام", callback_data: "maint:health" }, { text: "🔍 فحص سريع", callback_data: "maint:scan" }],
          [{ text: "🧠 تشخيص AI", callback_data: "maint:diagnose" }],
          [{ text: "🚀 تنفيذ ذكي شامل", callback_data: "exec:auto" }],
          [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
        ]},
      });
      return;
    }
    if (data === "maint:health") {
      await bot.sendMessage(chatId, "⏳ جاري فحص حالة النظام...");
      try {
        const { systemHealthCheck } = await import("../hayo/services/security.js");
        const health = await systemHealthCheck();
        const checks = Object.entries(health.checks).map(([k, v]: [string, any]) => `${v.ok ? "✅" : "❌"} ${k}: ${v.latency || v.error || "OK"}`).join("\n");
        await bot.sendMessage(chatId, `🏥 *حالة النظام: ${health.status}*\n\n${checks}`, { parse_mode: "Markdown" });
      } catch (e: any) { await bot.sendMessage(chatId, `❌ خطأ: ${e.message}`); }
      return;
    }
    if (data === "maint:scan") {
      await bot.sendMessage(chatId, "⏳ جاري الفحص السريع...");
      try {
        const { quickScan } = await import("../hayo/services/maintenance.js");
        const result = quickScan(process.cwd());
        const errors = result.diagnostics.filter(d => d.status === "error").length;
        const warnings = result.diagnostics.filter(d => d.status === "warning").length;
        await bot.sendMessage(chatId, `🔍 *نتيجة الفحص: ${result.score}/100*\n\n📁 ${result.scannedFiles} ملف | ${result.scannedLines} سطر\n❌ ${errors} أخطاء | ⚠️ ${warnings} تحذيرات`, { parse_mode: "Markdown" });
      } catch (e: any) { await bot.sendMessage(chatId, `❌ خطأ: ${e.message}`); }
      return;
    }
    if (data === "maint:diagnose") {
      bridgeSession.mode = "maintenance"; bridgeSession.subStep = "diagnose_input";
      await bot.sendMessage(chatId, "🧠 اكتب وصف المشكلة أو الصفحة المراد فحصها:");
      return;
    }

    // ── Pair selected ─────────────────────────────────────────
    if (data.startsWith("pair:")) {
      session.pair = data.split(":")[1];
      session.tf   = undefined;
      await sendTfMenu(chatId, msgId);
      return;
    }

    // ── Timeframe selected ────────────────────────────────────
    if (data.startsWith("tf:")) {
      session.tf = data.split(":")[1];
      if (!session.pair) { await sendPairsMenu(chatId, msgId); return; }
      await sendAnalysisMenu(chatId, msgId);
      return;
    }

    // ── Back navigation ───────────────────────────────────────
    if (data === "back:pairs") {
      session.pair = undefined;
      session.tf   = undefined;
      await sendPairsMenu(chatId, msgId);
      return;
    }
    if (data === "back:timeframes") {
      session.tf = undefined;
      if (!session.pair) { await sendPairsMenu(chatId, msgId); return; }
      await sendTfMenu(chatId, msgId);
      return;
    }

    // ── Auto-signals menu ─────────────────────────────────────
    if (data === "auto:menu") {
      await sendAutoMenu(chatId, msgId);
      return;
    }

    // ── Auto-signals settings ─────────────────────────────────
    if (data === "auto:noop") return;

    if (data === "auto:toggle") {
      autoConfig.enabled = !autoConfig.enabled;
      restartAutoScanner(bot, ownerChatId, lastSignalTimeLocal);
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data.startsWith("auto:cons:")) {
      autoConfig.minConsensus = parseInt(data.split(":")[2]);
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data.startsWith("auto:aiconf:")) {
      autoConfig.minAIConfidence = parseInt(data.split(":")[2]);
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data.startsWith("auto:pair:")) {
      const p = data.split(":")[2];
      if (p === "ALL") {
        const allKeys = Object.keys(PAIRS);
        autoConfig.pairs = autoConfig.pairs.length === allKeys.length ? [] : [...allKeys];
      } else if (autoConfig.pairs.includes(p)) {
        autoConfig.pairs = autoConfig.pairs.filter(x=>x!==p);
      } else {
        autoConfig.pairs.push(p);
      }
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data.startsWith("auto:tf:")) {
      const t = data.split(":")[2];
      if (autoConfig.timeframes.includes(t)) {
        autoConfig.timeframes = autoConfig.timeframes.filter(x=>x!==t);
      } else {
        autoConfig.timeframes.push(t);
      }
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data.startsWith("auto:interval:")) {
      autoConfig.intervalMinutes = parseInt(data.split(":")[2]);
      if (autoConfig.enabled) restartAutoScanner(bot, ownerChatId, lastSignalTimeLocal);
      await sendAutoMenu(chatId, msgId);
      return;
    }

    // ── Convergence (التطابق) ────────────────────────────────
    if (data === "conv:menu") {
      const c = convergenceConfig;
      const text = [
        `🎯 <b>نظام التطابق</b>`,
        ``,
        `الحالة: ${c.enabled ? "✅ <b>مفعّل</b>" : "❌ <b>معطّل</b>"}`,
        `الفحص: كل <code>${c.intervalMinutes}</code> دقائق`,
        `الأزواج: جميع الأزواج (${Object.keys(PAIRS).length})`,
        `الفريمات: <code>1م + 5م + 15م</code>`,
        ``,
        `<i>يفحص تطابق الاتجاه في 3 فريمات + تأكيد AI</i>`,
        `<i>عند التطابق تصل إشارة تلقائية</i>`,
      ].join("\n");

      const kb: TelegramBot.InlineKeyboardMarkup = {
        inline_keyboard: [
          [{ text: c.enabled ? "🔴 إيقاف التطابق" : "🟢 تفعيل التطابق", callback_data: "conv:toggle" }],
          [{ text: "━━ فترة الفحص ━━", callback_data: "conv:noop" }],
          [
            { text: `${c.intervalMinutes===1?"✅ ":""}1د`, callback_data: "conv:int:1" },
            { text: `${c.intervalMinutes===2?"✅ ":""}2د`, callback_data: "conv:int:2" },
            { text: `${c.intervalMinutes===3?"✅ ":""}3د`, callback_data: "conv:int:3" },
            { text: `${c.intervalMinutes===5?"✅ ":""}5د`, callback_data: "conv:int:5" },
          ],
          [
            { text: `${c.intervalMinutes===7?"✅ ":""}7د`, callback_data: "conv:int:7" },
            { text: `${c.intervalMinutes===10?"✅ ":""}10د`, callback_data: "conv:int:10" },
            { text: `${c.intervalMinutes===15?"✅ ":""}15د`, callback_data: "conv:int:15" },
          ],
          [{ text: "▶️ فحص فوري الآن", callback_data: "conv:now" }],
          [{ text: "◀️ رجوع", callback_data: "back:pairs" }],
        ],
      };

      if (msgId) {
        await bot.editMessageText(text, { chat_id: chatId, message_id: msgId, parse_mode: "HTML", reply_markup: kb });
      } else {
        await bot.sendMessage(chatId, text, { parse_mode: "HTML", reply_markup: kb });
      }
      return;
    }

    if (data === "conv:noop" || data === "noop") return;

    if (data === "conv:toggle") {
      convergenceConfig.enabled = !convergenceConfig.enabled;
      restartConvergenceScanner(bot, ownerChatId);
      await bot.editMessageText(
        `🎯 التطابق: ${convergenceConfig.enabled ? "✅ <b>مفعّل</b> — يتم فحص جميع الأزواج كل ${convergenceConfig.intervalMinutes} دقائق" : "❌ <b>معطّل</b>"}`,
        { chat_id: chatId, message_id: msgId, parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "◀️ إعدادات التطابق", callback_data: "conv:menu" }, { text: "🏠 القائمة", callback_data: "back:pairs" }]] } }
      );
      return;
    }

    if (data.startsWith("conv:int:")) {
      convergenceConfig.intervalMinutes = parseInt(data.split(":")[2]);
      if (convergenceConfig.enabled) restartConvergenceScanner(bot, ownerChatId);
      await bot.editMessageText(
        `🎯 فترة الفحص: <code>${convergenceConfig.intervalMinutes}</code> دقائق`,
        { chat_id: chatId, message_id: msgId, parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "◀️ إعدادات التطابق", callback_data: "conv:menu" }]] } }
      );
      return;
    }

    if (data === "conv:now") {
      await bot.editMessageText(
        `🎯 <b>جاري فحص التطابق...</b>\n⏳ فحص ${Object.keys(PAIRS).length} أزواج × 3 فريمات\nانتظر من فضلك...`,
        { chat_id: chatId, message_id: msgId, parse_mode: "HTML" }
      );
      const prevEnabled = convergenceConfig.enabled;
      convergenceConfig.enabled = true;
      await runConvergenceScan(bot, ownerChatId);
      convergenceConfig.enabled = prevEnabled;
      await bot.sendMessage(chatId, `✅ اكتمل فحص التطابق. سيتم إرسال أي إشارات متطابقة.`, {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "◀️ إعدادات التطابق", callback_data: "conv:menu" }, { text: "🏠 القائمة", callback_data: "back:pairs" }]] },
      });
      return;
    }

    // ── Analyze ───────────────────────────────────────────────
    if (data.startsWith("analyze:")) {
      const type = data.split(":")[1];
      const { pair, tf } = session;
      if (!pair || !tf) { await sendPairsMenu(chatId, msgId); return; }

      const p = PAIRS[pair];
      const loadingMsg = await bot.sendMessage(chatId,
        type === "quick"
          ? `${p.flag} <b>${p.label}</b> | <code>${tf}</code>\n\n⏳ جاري الحساب...`
          : `${p.flag} <b>${p.label}</b> | <code>${tf}</code>\n\n⏳ جاري جلب البيانات...\n🔄 10 استراتيجيات + 4 فلاتر\n🤖 5 نماذج AI تحلل...\n<i>لحظات (30-60 ثانية)</i>`,
        { parse_mode:"HTML" }
      );
      const loadMsgId = loadingMsg.message_id;

      try {
        const marketData = await fetchMarket(pair, TIMEFRAMES[tf]);
        if (type === "quick") {
          await bot.editMessageText(buildQuickMsg(pair, tf, marketData), {
            chat_id:chatId, message_id:loadMsgId, parse_mode:"HTML", reply_markup:afterResultKeyboard(),
          });
        } else {
          await bot.editMessageText(
            `${p.flag} <b>${p.label}</b> | <code>${tf}</code>\n\n✅ تم جلب البيانات\n📰 جلب الأخبار الاقتصادية...\n🤖 5 نماذج AI تحلل الآن...\n<i>لحظات (30-60 ثانية)</i>`,
            { chat_id:chatId, message_id:loadMsgId, parse_mode:"HTML" }
          );
          const news = await fetchEconomicNews(pair);
          const aiResults = await runAI(pair, tf, marketData, news);
          await bot.editMessageText(buildAIMsg(pair, tf, marketData, aiResults, false, news), {
            chat_id:chatId, message_id:loadMsgId, parse_mode:"HTML", reply_markup:afterResultKeyboard(),
          });
        }
      } catch (err: any) {
        try {
          await bot.editMessageText(`❌ خطأ: ${err.message}\n\nاضغط /menu للمحاولة مجدداً`,
            { chat_id:chatId, message_id:loadMsgId, parse_mode:"HTML" });
        } catch {}
      }
      return;
    }

    } catch (outerErr: any) {
      console.error("[TelegramBot] Callback handler error:", outerErr?.message || outerErr);
    }
  });

  // ── Unknown text ───────────────────────────────────────────────
  bot.on("message", async (msg) => {
    try {
      if (!isOwner(msg.chat.id)) return;
      if (!msg.text || msg.text.startsWith("/")) return;

      const chatId = msg.chat.id;
      const text = msg.text.trim();
      const bs = getBridgeSession(chatId);

      // ═══ Bridge Mode Processing ═══
      if (bs.mode) {
        const APP_URL = process.env.APP_URL || "http://localhost:5000";

        // ── Chat AI ──
        if (bs.mode === "chat") {
          await bot.sendMessage(chatId, "⏳ AI يفكر...");
          try {
            const { callPowerAI } = await import("../hayo/providers.js");
            const result = await callPowerAI("أنت مساعد ذكي شامل. أجب بدقة وإيجاز.", text, 4000);
            await safeSend(chatId, `🤖 *${result.modelUsed}:*\n\n${result.content}`, { reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── Code Agent ──
        if (bs.mode === "agent") {
          await bot.sendMessage(chatId, "⏳ وكيل الكود يعمل...");
          try {
            const { callPowerAI } = await import("../hayo/providers.js");
            const result = await callPowerAI("أنت مبرمج خبير. اكتب كود نظيف وقابل للتشغيل مع شرح.", text, 8000);
            await safeSend(chatId, `💻 *الكود:*\n\n${result.content}`, { reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── App Builder ──
        if (bs.mode === "appbuilder") {
          bs.mode = undefined;
          const appDesc = text;
          const appName = text.substring(0, 28).trim() || "HayoApp";

          await bot.sendMessage(chatId,
            `📱 *بدء بناء التطبيق*\n\n` +
            `📝 الوصف: ${appDesc.substring(0, 120)}\n\n` +
            `⏳ الخطوات:\n1️⃣ توليد الكود بالذكاء الاصطناعي\n2️⃣ مراجعة وإصلاح الكود\n3️⃣ إرسال للبناء على Expo EAS\n4️⃣ إشعارك عند الانتهاء\n\n` +
            `⏱️ المدة المتوقعة: 10-20 دقيقة`,
            { parse_mode: "Markdown" }
          );

          // Run build pipeline in background — don't await
          (async () => {
            try {
              const { callPowerAI } = await import("../hayo/providers.js");
              const { createExpoProject, submitEASBuild, aiReviewAndFix, checkEASBuildStatus, cleanupProjectDir } = await import("../hayo/services/eas-builder.js");

              // ── Step 1: Generate code ──
              await bot.sendMessage(chatId, "1️⃣ 🤖 جاري توليد كود التطبيق...");
              const codeResult = await callPowerAI(
                `أنت مطور React Native/Expo محترف. أنشئ كود App.tsx كامل وجاهز للبناء.
القواعد الصارمة:
- ملف واحد فقط (App.tsx) يبدأ بـ import React ويحتوي export default
- الحزم المسموح بها فقط: react-native, expo-status-bar, @expo/vector-icons, expo-linear-gradient, expo-haptics, expo-blur, @react-native-async-storage/async-storage, expo-clipboard
- ممنوع: react-navigation, expo-router, expo-camera, expo-av, expo-font, useFonts
- ممنوع: registerRootComponent في App.tsx (يكون في index.js منفصل)
- ممنوع: StatusBar من react-native — استخدم expo-status-bar
- استخدم فقط: fontFamily: "sans-serif" أو "monospace"
- أعد الكود فقط بدون أي شرح`,
                `أنشئ تطبيق موبايل: ${appDesc}`, 10000
              );

              let rawCode = codeResult.content.replace(/^```(?:tsx?|javascript|jsx|js)?\n?/im, "").replace(/\n?```\s*$/im, "").trim();

              // ── Step 2: AI Review & Fix ──
              await bot.sendMessage(chatId, "2️⃣ 🔍 مراجعة الكود وإصلاح المشاكل...");
              const reviewed = await aiReviewAndFix(rawCode);
              const finalCode = reviewed.fixedCode;

              if (reviewed.issues.length > 0) {
                await bot.sendMessage(chatId, `🔧 تم إصلاح ${reviewed.issues.length} مشكلة:\n• ${reviewed.issues.slice(0, 3).join("\n• ")}`);
              }

              // ── Step 3: Create Expo Project ──
              await bot.sendMessage(chatId, "3️⃣ 📦 إنشاء مشروع Expo وتثبيت الحزم (4-6 دقائق)...");
              const { projectDir, slug } = await createExpoProject(appName, finalCode);

              // ── Step 4: Submit to EAS ──
              await bot.sendMessage(chatId, "4️⃣ 🚀 إرسال للبناء على Expo EAS...");
              let buildResult;
              try {
                buildResult = await submitEASBuild(projectDir, slug);
              } catch (buildErr: any) {
                // If first try fails, run AI fix with the error and retry once
                await bot.sendMessage(chatId, "⚠️ فشل أولي — جاري إصلاح الكود بناءً على الخطأ...");
                const retried = await aiReviewAndFix(finalCode, buildErr.message);
                const { projectDir: pDir2, slug: slug2 } = await createExpoProject(appName + "2", retried.fixedCode);
                buildResult = await submitEASBuild(pDir2, slug2);
                cleanupProjectDir(projectDir);
              }

              await bot.sendMessage(chatId,
                `✅ *تم إرسال البناء!*\n\n` +
                `🆔 معرّف البناء: \`${buildResult.expoJobId}\`\n` +
                `📊 متابعة التقدم:\n${buildResult.buildLogsUrl}\n\n` +
                `⏱️ سيستغرق البناء 8-15 دقيقة على Expo EAS.\nسأُعلمك فور الانتهاء!`,
                { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "📊 متابعة البناء", url: buildResult.buildLogsUrl }], [{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } }
              );

              // ── Step 5: Poll for completion ──
              let attempts = 0;
              const maxAttempts = 40; // 40 * 30s = 20 min
              const pollTimer = setInterval(async () => {
                attempts++;
                try {
                  const status = await checkEASBuildStatus(buildResult.expoJobId, buildResult.expoSlug);

                  if (status.status === "finished" && status.downloadUrl) {
                    clearInterval(pollTimer);
                    cleanupProjectDir(projectDir);
                    await bot.sendMessage(chatId,
                      `🎉 *اكتمل البناء!*\n\n` +
                      `📥 رابط التحميل:\n${status.downloadUrl}\n\n` +
                      `⏰ الرابط صالح لـ 30 يوماً`,
                      { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "📥 تحميل APK", url: status.downloadUrl }], [{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } }
                    );
                  } else if (status.status === "errored") {
                    clearInterval(pollTimer);
                    cleanupProjectDir(projectDir);
                    await bot.sendMessage(chatId,
                      `❌ *فشل البناء*\n\n${status.errorMessage || "خطأ غير محدد"}\n\n` +
                      `🔗 السجلات الكاملة:\n${buildResult.buildLogsUrl}`,
                      { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "📋 عرض السجلات", url: buildResult.buildLogsUrl }], [{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } }
                    );
                  } else if (status.status === "cancelled") {
                    clearInterval(pollTimer);
                    cleanupProjectDir(projectDir);
                    await bot.sendMessage(chatId, "🚫 تم إلغاء البناء");
                  } else if (attempts >= maxAttempts) {
                    clearInterval(pollTimer);
                    await bot.sendMessage(chatId,
                      `⏰ *انتهت مهلة المتابعة*\n\nيمكنك متابعة البناء يدوياً:\n${buildResult.buildLogsUrl}`,
                      { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "📊 متابعة البناء", url: buildResult.buildLogsUrl }]] } }
                    );
                  }
                } catch { /* polling error — ignore, try again */ }
              }, 30_000); // poll every 30 seconds

            } catch (e: any) {
              await bot.sendMessage(chatId, `❌ *خطأ في البناء*\n\n${e.message?.substring(0, 400) || "خطأ غير معروف"}`, { parse_mode: "Markdown" });
            }
          })();

          return;
        }

        // ── Office: PPTX ──
        if (bs.mode === "office" && bs.subStep === "pptx") {
          await bot.sendMessage(chatId, "⏳ 📊 جاري إنشاء العرض التقديمي...");
          try {
            const res = await fetch(`${APP_URL}/api/office/generate-pptx`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ topic: text, slideCount: 10, style: "professional", language: "ar" }),
            });
            if (res.ok) {
              const buffer = await res.arrayBuffer();
              await bot.sendDocument(chatId, Buffer.from(buffer), { caption: `📊 ${text}` }, { filename: `${text.substring(0, 20)}.pptx`, contentType: "application/vnd.openxmlformats-officedocument.presentationml.presentation" });
            } else {
              await bot.sendMessage(chatId, "❌ فشل الإنشاء — جرّب من المنصة مباشرة");
            }
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          bs.mode = undefined;
          return;
        }

        // ── Office: Word ──
        if (bs.mode === "office" && bs.subStep === "word") {
          await bot.sendMessage(chatId, "⏳ 📝 جاري إنشاء التقرير...");
          try {
            const res = await fetch(`${APP_URL}/api/office/generate-report`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ topic: text, type: "business", language: "ar", pageCount: 5 }),
            });
            if (res.ok) {
              const buffer = await res.arrayBuffer();
              await bot.sendDocument(chatId, Buffer.from(buffer), { caption: `📝 ${text}` }, { filename: `تقرير-${text.substring(0, 15)}.docx`, contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" });
            } else {
              await bot.sendMessage(chatId, "❌ فشل الإنشاء");
            }
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          bs.mode = undefined;
          return;
        }

        // ── Studies ──
        if (bs.mode === "studies" && bs.subStep === "study_input") {
          const category = bs.data?.category || "general";
          await bot.sendMessage(chatId, `⏳ 📊 جاري إنشاء الدراسة (${category})... قد يستغرق دقيقتين`);
          try {
            const res = await fetch(`${APP_URL}/api/studies/generate`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ category, userInput: text, detailLevel: "detailed" }),
            });
            const data = await res.json();
            if (data.study) {
              await safeSend(chatId, `📊 *الدراسة — ${category}*\n\n${data.study}\n\n🤖 نموذج: ${data.modelUsed || "AI"}`, { reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
            } else {
              await bot.sendMessage(chatId, `❌ ${data.error || "فشل الإنشاء"}`);
            }
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          bs.mode = undefined;
          return;
        }

        // ── EA Factory ──
        if (bs.mode === "ea" && (bs.subStep === "ea_params" || bs.subStep === "waiting")) {
          await bot.sendMessage(chatId, "⏳ ⚙️ جاري توليد كود EA بـ MQL5...");
          try {
            const { callPowerAI } = await import("../hayo/providers.js");
            const eaType = bs.data?.eaType || "custom";
            const eaSystemPrompts: Record<string, string> = {
              ma_cross:     "أنت خبير في برمجة MQL5. اكتب Expert Advisor كامل لاستراتيجية تقاطع المتوسطات المتحركة. اشمل: إدارة المخاطر، وقف الخسارة، هدف الربح، TrailingStop اختياري. أعد الكود فقط مع تعليقات عربية.",
              rsi_reversal: "أنت خبير في برمجة MQL5. اكتب Expert Advisor كامل لاستراتيجية RSI العكسية (ذروة شراء/بيع). اشمل: إدارة المخاطر، وقف الخسارة، هدف الربح. أعد الكود فقط مع تعليقات عربية.",
              breakout:     "أنت خبير في برمجة MQL5. اكتب Expert Advisor كامل لاستراتيجية اختراق النطاق (High/Low Breakout). اشمل: إدارة المخاطر، وقف الخسارة، هدف الربح. أعد الكود فقط مع تعليقات عربية.",
              bollinger:    "أنت خبير في برمجة MQL5. اكتب Expert Advisor كامل لاستراتيجية بولنجر باند (Bollinger Bands). اشمل: إدارة المخاطر، وقف الخسارة، هدف الربح. أعد الكود فقط مع تعليقات عربية.",
              custom:       "أنت خبير في برمجة MQL5. اكتب Expert Advisor كامل للاستراتيجية الموصوفة. اشمل: إدارة المخاطر، وقف الخسارة، هدف الربح. أعد الكود فقط مع تعليقات عربية.",
            };
            const result = await callPowerAI(eaSystemPrompts[eaType] || eaSystemPrompts.custom, `المعاملات: ${text}`, 8000);
            // Send as file if code is long, otherwise as message
            const code = result.content;
            if (code.length > 2000) {
              const buf = Buffer.from(code, "utf-8");
              await bot.sendDocument(chatId, buf,
                { caption: `⚙️ EA جاهز (${eaType}) — ${text.substring(0, 40)}` },
                { filename: `EA_${eaType}_${Date.now()}.mq5`, contentType: "text/plain" }
              );
            } else {
              await safeSend(chatId, `⚙️ *كود EA جاهز:*\n\n\`\`\`mql5\n${code}\n\`\`\``, {
                reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] }
              });
            }
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          bs.mode = undefined;
          return;
        }

        // ── Prompt Factory ──
        if (bs.mode === "prompt") {
          await bot.sendMessage(chatId, "⏳ 🪄 جاري توليد البرومبت...");
          try {
            const res = await fetch(`${APP_URL}/api/prompt-factory/generate`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ request: text }),
            });
            const data = await res.json();
            await safeSend(chatId, `🪄 *البرومبت الاحترافي:*\n\n${data.result || "فشل"}`, { reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── Image Generation ──
        if (bs.mode === "image") {
          await bot.sendMessage(chatId, "⏳ 🎨 جاري توليد الصورة...");
          try {
            const res = await fetch(`${APP_URL}/api/chat/generate-image`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ prompt: text }),
            });
            const data = await res.json();
            if (data.imageUrl) {
              if (data.imageUrl.startsWith("data:")) {
                // SVG data URL — send as document
                const svgBuffer = Buffer.from(data.imageUrl.split(",")[1], "base64");
                await bot.sendDocument(chatId, svgBuffer, { caption: `🎨 ${text}` }, { filename: "image.svg", contentType: "image/svg+xml" });
              } else {
                await bot.sendPhoto(chatId, data.imageUrl, { caption: `🎨 ${text}\n🤖 ${data.model}` });
              }
            } else {
              await bot.sendMessage(chatId, `❌ ${data.error || "فشل التوليد"}`);
            }
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── Maintenance Diagnose ──
        if (bs.mode === "maintenance" && bs.subStep === "diagnose_input") {
          await bot.sendMessage(chatId, "⏳ 🧠 AI يشخّص المشكلة...");
          try {
            const { aiDiagnose, getProjectStructure } = await import("../hayo/services/maintenance.js");
            const root = process.cwd();
            const structure = getProjectStructure(root);
            const files = structure.files.slice(0, 8).map(f => f.path);
            const result = await aiDiagnose(files, root, text);
            let reply = `🧠 *تقرير التشخيص:*\n\n${result.report.substring(0, 3000)}`;
            if (result.fixes?.length > 0) {
              reply += `\n\n🔧 *${result.fixes.length} إصلاحات مقترحة:*\n`;
              result.fixes.slice(0, 5).forEach((f: any) => { reply += `\n📄 ${f.file}: ${f.description.substring(0, 100)}`; });
            }
            await safeSend(chatId, reply, { reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          bs.mode = undefined;
          return;
        }

        // ── Executive Agent — Guided Fix ──
        if (bs.mode === "executive" && bs.subStep === "exec_input") {
          await bot.sendMessage(chatId, `⏳ 🚀 المنفّذ الذكي يعمل على: "${text.substring(0, 60)}..."\n\n📊 المراحل: فحص → تشخيص → إصلاح`);
          bs.mode = undefined; bs.subStep = undefined;
          (async () => {
            try {
              const { aiDiagnose, getProjectStructure, quickScan } = await import("../hayo/services/maintenance.js");
              const root = process.cwd();
              // Step 1: Scan
              await bot.sendMessage(chatId, "1️⃣ 🔍 جاري فحص المشروع...");
              const scan = quickScan(root);
              await bot.sendMessage(chatId, `✅ الفحص: ${scan.score}/100 | ${scan.scannedFiles} ملف | ${scan.diagnostics.filter((d: any) => d.status === "error").length} أخطاء`);
              // Step 2: Diagnose with user context
              await bot.sendMessage(chatId, "2️⃣ 🧠 AI يشخّص المشكلة المحددة...");
              const structure = getProjectStructure(root);
              const files = structure.files.slice(0, 10).map((f: any) => f.path);
              const diagnosis = await aiDiagnose(files, root, text);
              await bot.sendMessage(chatId, `✅ التشخيص جاهز — ${diagnosis.fixes?.length || 0} إصلاح مقترح`);
              // Step 3: Report
              let reply = `🚀 *نتيجة التنفيذ الذكي:*\n\n📋 *السياق:* ${text.substring(0, 100)}\n\n`;
              reply += `📊 *الفحص:* ${scan.score}/100\n`;
              reply += `\n🧠 *التشخيص:*\n${diagnosis.report.substring(0, 1500)}`;
              if (diagnosis.fixes?.length > 0) {
                reply += `\n\n🔧 *الإصلاحات المقترحة (${diagnosis.fixes.length}):*\n`;
                diagnosis.fixes.slice(0, 5).forEach((f: any) => {
                  reply += `\n📄 ${f.file || "?"}: ${(f.description || "").substring(0, 80)}`;
                });
              }
              await safeSend(chatId, reply.substring(0, 4000), {
                reply_markup: { inline_keyboard: [
                  [{ text: "🔧 إصلاح آخر", callback_data: "exec:fix_page" }, { text: "🚀 تنفيذ شامل", callback_data: "exec:auto" }],
                  [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
                ]},
              });
            } catch (e: any) {
              await bot.sendMessage(chatId, `❌ خطأ: ${e.message?.substring(0, 300)}`);
            }
          })();
          return;
        }

        // ── Mind Map ──
        if (bs.mode === "mindmap") {
          await bot.sendMessage(chatId, "⏳ 🗺️ جاري إنشاء الخريطة الذهنية...");
          bs.mode = undefined;
          try {
            const { callPowerAI } = await import("../hayo/providers.js");
            const result = await callPowerAI(
              `أنت خبير في الخرائط الذهنية. أنشئ خريطة ذهنية منظمة ومفصلة بالعربية.
استخدم هذا التنسيق بالضبط:
🎯 المحور الرئيسي: [الموضوع]

📌 الفرع 1: [اسم]
  ├── نقطة فرعية
  ├── نقطة فرعية
  └── نقطة فرعية

📌 الفرع 2: [اسم]
  ├── نقطة فرعية
  └── نقطة فرعية

[كرر لـ 5-7 فروع رئيسية]

💡 الخلاصة: [ملاحظة ختامية]`,
              `أنشئ خريطة ذهنية شاملة حول: ${text}`, 3000
            );
            await safeSend(chatId, `🗺️ *خريطة ذهنية: ${text.substring(0, 40)}*\n\n${result.content}`, {
              reply_markup: { inline_keyboard: [[{ text: "🗺️ موضوع جديد", callback_data: "bridge:mindmap" }, { text: "🏠 القائمة", callback_data: "bridge:main" }]] },
            });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── OSINT ──
        if (bs.mode === "osint") {
          await bot.sendMessage(chatId, `⏳ 🔍 OSINT يحلل الهدف: "${text.substring(0, 50)}"...`);
          bs.mode = undefined;
          try {
            const { callPowerAI } = await import("../hayo/providers.js");
            const result = await callPowerAI(
              `أنت محلل OSINT (استخبارات المصادر المفتوحة) خبير. قدّم تحليلاً شاملاً لأي هدف بناءً على المعلومات العامة المتاحة.

اشمل دائماً:
🎯 **ملف الهدف**: معلومات أساسية
🔗 **الروابط الرقمية**: مواقع، شبكات اجتماعية متوقعة
📊 **التحليل**: أنماط، سلوك، معلومات مهنية
⚠️ **نقاط الاهتمام**: أي معلومات لافتة
🔒 **ملاحظة**: هذا للأغراض التعليمية والمشروعة فقط

أجب بالعربية بشكل مفصل ومنظم.`,
              `هدف OSINT للتحليل: ${text}`, 4000
            );
            await safeSend(chatId, `🔍 *تحليل OSINT: ${text.substring(0, 40)}*\n\n${result.content}`, {
              reply_markup: { inline_keyboard: [[{ text: "🔍 هدف جديد", callback_data: "bridge:osint" }, { text: "🏠 القائمة", callback_data: "bridge:main" }]] },
            });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── Reverse Engineering ──
        if (bs.mode === "reverse") {
          await bot.sendMessage(chatId, "⏳ 🔬 جاري تحليل الكود بـ Claude Opus...");
          bs.mode = undefined;
          try {
            const { callProvider } = await import("../hayo/providers.js");
            const systemPrompt = `أنت خبير هندسة عكسية وأمن معلومات. حلّل الكود أو الطلب بعمق واشمل:
🔬 **ما يفعله الكود**: شرح مبسط وتقني
🏗️ **البنية والمعمارية**: الأنماط المستخدمة
⚠️ **الثغرات والمخاطر**: أي مشاكل أمنية أو تقنية
🔧 **التحسينات المقترحة**: كيف يمكن تحسينه
💡 **الخلاصة**: النقاط الرئيسية

أجب بالعربية مع أمثلة كود إن لزم.`;
            const result = await callProvider("claude", systemPrompt, `تحليل: ${text}`, 5000);
            await safeSend(chatId, `🔬 *تحليل الهندسة العكسية:*\n\n${result.content}`, {
              reply_markup: { inline_keyboard: [[{ text: "🔬 تحليل آخر", callback_data: "bridge:reverse" }, { text: "🏠 القائمة", callback_data: "bridge:main" }]] },
            });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }
      }

      // Default: show main menu
      await bot.sendMessage(chatId, "🏠 اختر قسم من القائمة:", { reply_markup: mainMenuKeyboard() });
    } catch {}
  });

  if (useWebhook && webhookUrl) {
    // Webhook mode — app.ts handles setWebhook registration externally
    console.log(`[TelegramBot] ✅ Bot started in WEBHOOK mode — owner only (ID: ${ownerChatId})`);
  } else {
    // Polling mode (development)
    bot.on("polling_error", (err) => {
      console.warn("[TelegramBot] Polling error (suppressed):", (err as any).message?.slice(0, 100));
    });
    console.log(`[TelegramBot] ✅ Bot started in POLLING mode — owner only (ID: ${ownerChatId})`);
  }

  if (botRole === "trading") {
    _botRef = bot;
    _ownerRef = ownerChatId;
    if (convergenceConfig.enabled) {
      console.log(`[Convergence] Auto-starting convergence scanner (interval: ${convergenceConfig.intervalMinutes}min)`);
      restartConvergenceScanner(bot, ownerChatId);
    }
  }

  return bot;
}
