/**
 * OANDA Forex Trading Service
 * Real API integration with OANDA v20 REST API
 * Supports: market orders, limit orders, position management, account info
 * 
 * Docs: https://developer.oanda.com/rest-live-v20/introduction/
 */

// ─── Types ───────────────────────────────────────────────────────────
export interface OandaConfig {
  apiToken: string;
  accountId: string;
  environment: "practice" | "live";
}

export interface OandaAccountInfo {
  id: string;
  currency: string;
  balance: number;
  unrealizedPL: number;
  marginUsed: number;
  marginAvailable: number;
  openTradeCount: number;
  openPositionCount: number;
}

export interface OandaOrder {
  instrument: string;      // e.g. "EUR_USD"
  units: number;           // positive = buy, negative = sell
  type: "MARKET" | "LIMIT" | "STOP";
  price?: number;          // for LIMIT/STOP
  stopLossPrice?: number;
  takeProfitPrice?: number;
  trailingStopDistance?: number;
}

export interface OandaOrderResult {
  success: boolean;
  orderId?: string;
  tradeId?: string;
  price?: number;
  units?: number;
  error?: string;
}

export interface OandaPosition {
  instrument: string;
  long: { units: number; averagePrice: number; unrealizedPL: number };
  short: { units: number; averagePrice: number; unrealizedPL: number };
}

export interface OandaPrice {
  instrument: string;
  bid: number;
  ask: number;
  spread: number;
  time: string;
}

// ─── Base URL ────────────────────────────────────────────────────────
function getBaseUrl(env: "practice" | "live"): string {
  return env === "live"
    ? "https://api-fxtrade.oanda.com/v3"
    : "https://api-fxpractice.oanda.com/v3";
}

function getStreamUrl(env: "practice" | "live"): string {
  return env === "live"
    ? "https://stream-fxtrade.oanda.com/v3"
    : "https://stream-fxpractice.oanda.com/v3";
}

// ─── API Helper ──────────────────────────────────────────────────────
async function oandaFetch(
  config: OandaConfig,
  path: string,
  method: "GET" | "POST" | "PUT" | "DELETE" = "GET",
  body?: any
): Promise<any> {
  const url = `${getBaseUrl(config.environment)}${path}`;
  const headers: Record<string, string> = {
    "Authorization": `Bearer ${config.apiToken}`,
    "Content-Type": "application/json",
    "Accept-Datetime-Format": "UNIX",
  };

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(15_000),
  });

  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    const errMsg = (errBody as any)?.errorMessage || (errBody as any)?.rejectReason || `HTTP ${res.status}`;
    throw new Error(`OANDA Error: ${errMsg}`);
  }

  return res.json();
}

// ─── Account Info ────────────────────────────────────────────────────
export async function getAccountInfo(config: OandaConfig): Promise<OandaAccountInfo> {
  const data = await oandaFetch(config, `/accounts/${config.accountId}/summary`);
  const acc = data.account;
  return {
    id: acc.id,
    currency: acc.currency,
    balance: parseFloat(acc.balance),
    unrealizedPL: parseFloat(acc.unrealizedPL),
    marginUsed: parseFloat(acc.marginUsed),
    marginAvailable: parseFloat(acc.marginAvailable),
    openTradeCount: acc.openTradeCount,
    openPositionCount: acc.openPositionCount,
  };
}

// ─── Get Prices ──────────────────────────────────────────────────────
export async function getPrices(config: OandaConfig, instruments: string[]): Promise<OandaPrice[]> {
  const query = instruments.join(",");
  const data = await oandaFetch(config, `/accounts/${config.accountId}/pricing?instruments=${query}`);
  return (data.prices || []).map((p: any) => ({
    instrument: p.instrument,
    bid: parseFloat(p.bids?.[0]?.price || "0"),
    ask: parseFloat(p.asks?.[0]?.price || "0"),
    spread: parseFloat(p.asks?.[0]?.price || "0") - parseFloat(p.bids?.[0]?.price || "0"),
    time: p.time,
  }));
}

// ─── Place Order ─────────────────────────────────────────────────────
export async function placeOrder(config: OandaConfig, order: OandaOrder): Promise<OandaOrderResult> {
  const orderBody: any = {
    order: {
      type: order.type,
      instrument: order.instrument,
      units: String(order.units),
      timeInForce: order.type === "MARKET" ? "FOK" : "GTC",
      positionFill: "DEFAULT",
    },
  };

  if (order.type === "LIMIT" && order.price) {
    orderBody.order.price = String(order.price);
  }
  if (order.type === "STOP" && order.price) {
    orderBody.order.price = String(order.price);
  }

  // Stop Loss
  if (order.stopLossPrice) {
    orderBody.order.stopLossOnFill = {
      price: String(order.stopLossPrice),
      timeInForce: "GTC",
    };
  }

  // Take Profit
  if (order.takeProfitPrice) {
    orderBody.order.takeProfitOnFill = {
      price: String(order.takeProfitPrice),
    };
  }

  // Trailing Stop
  if (order.trailingStopDistance) {
    orderBody.order.trailingStopLossOnFill = {
      distance: String(order.trailingStopDistance),
    };
  }

  try {
    const data = await oandaFetch(config, `/accounts/${config.accountId}/orders`, "POST", orderBody);

    // Check if order was filled immediately (market order)
    if (data.orderFillTransaction) {
      return {
        success: true,
        orderId: data.orderFillTransaction.id,
        tradeId: data.orderFillTransaction.tradeOpened?.tradeID || data.orderFillTransaction.id,
        price: parseFloat(data.orderFillTransaction.price),
        units: parseInt(data.orderFillTransaction.units),
      };
    }

    // Order created but not filled yet (limit/stop)
    if (data.orderCreateTransaction) {
      return {
        success: true,
        orderId: data.orderCreateTransaction.id,
        price: order.price,
        units: order.units,
      };
    }

    // Order rejected
    if (data.orderRejectTransaction) {
      return {
        success: false,
        error: data.orderRejectTransaction.rejectReason || "Order rejected",
      };
    }

    return { success: true, orderId: "unknown" };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ─── Close Position ──────────────────────────────────────────────────
export async function closePosition(config: OandaConfig, instrument: string, side: "long" | "short" | "all" = "all"): Promise<OandaOrderResult> {
  const body: any = {};
  if (side === "long" || side === "all") body.longUnits = "ALL";
  if (side === "short" || side === "all") body.shortUnits = "ALL";

  try {
    const data = await oandaFetch(config, `/accounts/${config.accountId}/positions/${instrument}/close`, "PUT", body);
    return {
      success: true,
      orderId: data.longOrderFillTransaction?.id || data.shortOrderFillTransaction?.id || "closed",
      price: parseFloat(data.longOrderFillTransaction?.price || data.shortOrderFillTransaction?.price || "0"),
    };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ─── Get Open Positions ──────────────────────────────────────────────
export async function getOpenPositions(config: OandaConfig): Promise<OandaPosition[]> {
  const data = await oandaFetch(config, `/accounts/${config.accountId}/openPositions`);
  return (data.positions || []).map((p: any) => ({
    instrument: p.instrument,
    long: {
      units: parseInt(p.long?.units || "0"),
      averagePrice: parseFloat(p.long?.averagePrice || "0"),
      unrealizedPL: parseFloat(p.long?.unrealizedPL || "0"),
    },
    short: {
      units: Math.abs(parseInt(p.short?.units || "0")),
      averagePrice: parseFloat(p.short?.averagePrice || "0"),
      unrealizedPL: parseFloat(p.short?.unrealizedPL || "0"),
    },
  }));
}

// ─── Get Open Trades ─────────────────────────────────────────────────
export async function getOpenTrades(config: OandaConfig): Promise<any[]> {
  const data = await oandaFetch(config, `/accounts/${config.accountId}/openTrades`);
  return (data.trades || []).map((t: any) => ({
    id: t.id,
    instrument: t.instrument,
    units: parseInt(t.currentUnits),
    price: parseFloat(t.price),
    unrealizedPL: parseFloat(t.unrealizedPL),
    openTime: t.openTime,
    stopLoss: t.stopLossOrder?.price ? parseFloat(t.stopLossOrder.price) : null,
    takeProfit: t.takeProfitOrder?.price ? parseFloat(t.takeProfitOrder.price) : null,
  }));
}

// ─── Close Trade by ID ───────────────────────────────────────────────
export async function closeTrade(config: OandaConfig, tradeId: string): Promise<OandaOrderResult> {
  try {
    const data = await oandaFetch(config, `/accounts/${config.accountId}/trades/${tradeId}/close`, "PUT", { units: "ALL" });
    return {
      success: true,
      orderId: data.orderFillTransaction?.id || tradeId,
      price: parseFloat(data.orderFillTransaction?.price || "0"),
    };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ─── Test Connection ─────────────────────────────────────────────────
export async function testConnection(config: OandaConfig): Promise<{ success: boolean; info?: OandaAccountInfo; error?: string }> {
  try {
    const info = await getAccountInfo(config);
    return { success: true, info };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ─── Convert HAYO pair format to OANDA format ────────────────────────
export function toOandaInstrument(pair: string): string {
  // HAYO uses: EURUSD, GBPUSD, etc.
  // OANDA uses: EUR_USD, GBP_USD, etc.
  const clean = pair.replace(/[^A-Z]/g, "").toUpperCase();
  if (clean.length === 6) {
    return `${clean.slice(0, 3)}_${clean.slice(3)}`;
  }
  // Crypto: BTCUSD → BTC_USD
  if (clean.length === 7 && clean.startsWith("BTC")) {
    return `${clean.slice(0, 3)}_${clean.slice(3)}`;
  }
  // Gold: XAUUSD → XAU_USD
  if (clean.startsWith("XAU") || clean.startsWith("XAG")) {
    return `${clean.slice(0, 3)}_${clean.slice(3)}`;
  }
  return clean;
}

// ─── Auto-Execute Signal ─────────────────────────────────────────────
export async function autoExecuteSignal(
  config: OandaConfig,
  signal: {
    pair: string;
    direction: "BUY" | "SELL";
    confidence: number;
    stopLoss?: number;
    takeProfit?: number;
  },
  riskPercent: number = 1,
): Promise<OandaOrderResult & { riskInfo?: string }> {
  // 1. Get account info for position sizing
  const account = await getAccountInfo(config);
  
  // 2. Calculate position size based on risk %
  const riskAmount = account.balance * (riskPercent / 100);
  const instrument = toOandaInstrument(signal.pair);

  // 3. Get current price
  const prices = await getPrices(config, [instrument]);
  const price = prices[0];
  if (!price) throw new Error(`لم يتم العثور على سعر ${instrument}`);

  // 4. Calculate units based on SL distance
  let units = 1000; // default micro lot
  if (signal.stopLoss) {
    const slDistance = Math.abs(price.ask - signal.stopLoss);
    if (slDistance > 0) {
      // pip value calculation (simplified for major pairs)
      const pipSize = instrument.includes("JPY") ? 0.01 : 0.0001;
      const slPips = slDistance / pipSize;
      units = Math.floor(riskAmount / (slPips * (pipSize * 10))); // rough calculation
      units = Math.max(1, Math.min(units, 100000)); // clamp between 1 and 1 standard lot
    }
  }

  // 5. Place order
  const order: OandaOrder = {
    instrument,
    units: signal.direction === "BUY" ? units : -units,
    type: "MARKET",
    stopLossPrice: signal.stopLoss,
    takeProfitPrice: signal.takeProfit,
  };

  const result = await placeOrder(config, order);
  
  return {
    ...result,
    riskInfo: `المخاطرة: ${riskPercent}% = $${riskAmount.toFixed(2)} | الحجم: ${units} وحدة | السعر: ${price.ask.toFixed(5)}`,
  };
}
