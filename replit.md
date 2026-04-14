# HAYO AI — Workspace

## Overview

HAYO AI هو منصة ذكاء اصطناعي عربية-أولى (Arabic-first AI SaaS) مبنية على pnpm workspace monorepo بـ TypeScript.

## Stack

- **Monorepo**: pnpm workspaces
- **Node.js**: 24 | **TypeScript**: 5.9
- **Backend**: Express 5 + tRPC v11 + PostgreSQL + Drizzle ORM
- **Frontend**: React 18 + Vite + TailwindCSS + shadcn/ui (RTL عربي)
- **AI Models (Trading)**: Claude Opus 4 ✅ | Gemini 2.5 Pro ✅ | DeepSeek R1 ✅
- **AI Models (Chat)**: Claude Opus ✅ | GPT-4o ❌(billing) | Gemini Flash ✅ | Gemini Pro ✅ | DeepSeek ✅
- **Build**: esbuild (dist/index.mjs)

## Artifacts

| Artifact | Port | Status |
|---|---|---|
| API Server (`@workspace/api-server`) | 8080 | ✅ Running |
| HAYO AI Frontend (`@workspace/hayo-ai`) | 23836 | ✅ Running |
| Mockup Sandbox | 8082 | On-demand |

## REST Routes (8 total) — `artifacts/api-server/src/routes/`

| File | Endpoints |
|---|---|
| `health.ts` | GET /api/health |
| `chat-stream.ts` | POST /api/chat/stream (SSE), /generate-image, /generate-video |
| `office.ts` | POST /api/office/generate-pptx, /generate-report, /convert, /process-excel, /run-tool, /text-to-docx |
| `studies.ts` | POST /api/studies/generate, /follow-up, /export-docx |
| `prompt-factory.ts` | POST /api/prompt-factory/generate, /refine, /test |
| `reverse.ts` | POST /api/reverse/decompile, /analyze, /decompile-for-edit, /ai-modify, /ai-search, /ai-smart-modify, /rebuild, /clone, /intelligence-report, /regex-search |
| `telegram.ts` | GET /api/telegram/status, POST /setup, /test, /send |
| `extract-archive.ts` | POST /api/files/extract-archive |

## Telegram Bots

- **Bot 1** (Trading): `@HAYO_AI_Signals_bot` — token: `TELEGRAM_BOT_TOKEN`
- **Bot 2** (Bridge/Executive): `@ALEPPO_CANDLES6_bot` — token: `TELEGRAM_BRIDGE_BOT_TOKEN`
- **Owner ID**: 34498339 | **Mode**: Webhook v2 (`/api/telegram/wh2/`) — watchdog كل 3s
- **Webhook URL auto-detection**: REPLIT_DEV_DOMAIN → REPLIT_DOMAINS → APP_URL
- **sendToTelegram**: Uses `TELEGRAM_BOT_TOKEN` + `TELEGRAM_OWNER_CHAT_ID` env vars directly (no DB bot required). Sends FULL detailed message: indicators (RSI/MACD/SMA/BB/ATR/Stoch/ADX/Pivots) + all strategies + all filters + AI analysis per model + consensus box

## AI Provider Priority (callPowerAI)

1. Claude Opus 4.6 (`ANTHROPIC_API_KEY`) — PRIMARY ✅
2. DeepSeek Chat (`DEEPSEEK_API_KEY`) — SECONDARY ✅
3. GPT-4o (`OPENAI_API_KEY`) ✅
4. Gemini 2.5 Flash (`GOOGLE_API_KEY3`) ✅
5. DeepSeek Reasoner (آخر ملاذ)

## Key Services — `artifacts/api-server/src/hayo/services/`

- `presentation-generator.ts` — PPTX بـ PptxGenJS + AI
- `report-generator.ts` — Word DOCX بـ Markdown → DOCX
- `reverse-engineer.ts` (~4670 سطر) — APK/EXE/ELF/IPA/JAR/DEX/EX4/EX5/WASM/SO تحليل كامل + wasm2wat + objdump + readelf
- `file-converter.ts` — تحويل 30+ صيغة
- `oanda-trading.ts` — OANDA FX API
- **Telegram Trading Bot** (`src/telegram/bot.ts`):
  - Auto-Signals: Periodic scan with min consensus + AI confidence thresholds
  - **Convergence (التطابق)**: Scans ALL 18 pairs × 3 timeframes (1m, 5m, 15m). Sends alert only when all 3 TFs agree + AI confirms (≥2 models, ≥60% confidence). Cooldown: 1hr/pair. Configurable interval: 1-15 min. Auto-enabled on startup.
  - **18 pairs**: EUR/USD, USD/JPY, GBP/USD, GBP/JPY, USD/CHF, AUD/USD, NZD/USD, USD/CAD, EUR/GBP, EUR/JPY, EUR/CHF, AUD/CAD, XAU/USD, XAG/USD, BTC/USD, ETH/USD, US Oil, US30/DJI
- `eas-builder.ts` — Expo EAS بناء التطبيقات
- `osint.ts` — OSINT استخبارات
- `mindmap.ts` — خرائط ذهنية

## Key Commands

```bash
pnpm --filter @workspace/api-server run dev   # API Server
pnpm --filter @workspace/hayo-ai run dev      # Frontend
pnpm run typecheck                            # فحص TypeScript
```

## Secrets Required (Replit Secrets Tab 🔒)

```
ANTHROPIC_API_KEY      — Claude Opus 4.5
OPENAI_API_KEY         — GPT-4o + DALL-E 3
GOOGLE_API_KEY3        — Gemini 2.5 Flash/Pro
DEEPSEEK_API_KEY       — DeepSeek Chat/Reasoner
TWELVE_DATA_API_KEY    — بيانات التداول
TELEGRAM_BOT_TOKEN     — بوت التداول
TELEGRAM_BRIDGE_BOT_TOKEN — بوت العميل التنفيذي
EXPO_ACCESS_TOKEN      — EAS بناء تطبيقات
SESSION_SECRET         — JWT sessions
APP_URL                — رابط الخادم (للـ webhooks)
TELEGRAM_OWNER_CHAT_ID — 34498339 (owner ID)
```

## Admin

- **Password**: `6088amhA+`
- **Expo Project ID**: `8b4e647b-ba87-439b-a677-5047702a3ddb` (slug: `haio-ai-agent`, owner: ahmet80)

## Reverse Engineering Platform

- **12 Supported Formats**: APK, EXE, DLL, IPA, JAR, DEX, SO, WASM, EX4, EX5, ELF, MQL5
- **Tools**: JADX v1.5.0, APKTool v2.11.1, ADB v1.0.41, 7zz v24.09 (auto-install), wasm2wat, objdump, readelf, jarsigner, xxd
- **SSE Live Stream (REAL)**:
  - `POST /api/reverse/upload` — saves file, returns `uploadId`
  - `GET /api/reverse/stream/decompile?uploadId=xxx` — runs REAL apktool+jadx+readelf etc, streams every line via SSE, sends `event: result` with JSON at end
  - `GET /api/reverse/stream/clone?uploadId=xxx&opts={...}` — runs REAL clone process (decompile→modify→rebuild→sign), streams all steps
  - `GET /api/reverse/stream/download/:dlId` — downloads cloned file
  - `GET /api/reverse/stream/execute?cmd=...&args=[...]&cwd=...` — generic command execution (allowlist: 13 tools)
  - LiveTerminal component connects to SSE via single EventSource (no duplicate connections), receives `onResult` callback
- **Multer**: diskStorage (saves to /tmp/hayo_re_uploads/) — prevents OOM on large files
- **Keystore**: `/home/runner/debug.keystore` (pass: `android`, alias: `androiddebugkey`)
- **Upload Limit**: 500MB (admin), 100MB (free), 250MB (pro)
- **Features**: Decompile, Edit, Rebuild, Sign, Clone (REAL binary patching), AI Analysis, Intelligence Report, Regex Search, Smart Modify, Hex Dump (REAL), Undo/Redo
- **UI Tools Panel**: Wrench icon shows 12/12 tool status
- **No demo data**: All DEMO_USERS and demo-vuln endpoints removed — only real analysis
- **Clone (Real)**: 
  - **APK**: apktool decompile smali → pattern modify → rebuild → jarsigner sign
  - **EXE (NSIS/Electron/Tauri)**: 7zz extract → inner EXE detect → binary patch (JE→JMP, string nullify) → Tauri brotli asset scan → embedded JS/HTML patch → ZIP output
  - **EXE (Native/DLL/SO)**: Direct binary patching — x86 JE→JMP, JNE→JMP, xor eax→mov al, string replacement
  - **Tauri Brotli Assets**: `findTauriBrotliAssets()` scans markers (index.html, __TAURI, tauri://) ±128 bytes + broad scan; `patchTauriEmbeddedAssets()` decompresses, patches premium/license/ads/tracking in JS/HTML, recompresses (quality 11), writes back if size ≤ original; detects WebView apps loading external URLs
  - **JAR/AAR**: ZIP extract → Java/Kotlin source modify → repackage
  - **IPA**: ZIP extract → Swift/ObjC modify → repackage (needs Apple re-sign)
  - **Binary patches**: Ad domain nullify, premium method bypass (JE→JMP), tracking URL removal, license check skip

## AI Agent التنفيذي

- **Page**: `/ai-agent` — Admin-only
- **Backend Router**: `aiAgent` tRPC router in `ai-agent-router.ts` (execute, applyOps, readFile, projectTree)
- **Service**: `services/ai-agent.ts` — Claude Sonnet reads project tree, generates file operations (create/edit/delete/read)
- **Features**: 
  - Natural language commands (Arabic/English) → file operations
  - Auto-execute mode (applies changes immediately) or manual review
  - Conversation history for context
  - Project tree visualization
  - Smart context injection (reads relevant files based on command keywords)
- **Security**: Admin-only access, path sandboxing (PROJECT_ROOT only)

## Model Settings (System Prompts)

- **Page**: `/model-settings` — Admin-only
- **Backend**: `modelInstructions` tRPC router (getAll, get, update, reset) in `router.ts`
- **Service**: `system-prompts.ts` — in-memory store with defaults per model (claude, gpt-4o, deepseek, gemini, groq, mistral)
- **Frontend**: Uses `trpc.modelInstructions.getAll.useQuery()` + `.update.useMutation()` + `.reset.useMutation()` — saves to server
- **Integration**: `withModelInstruction()` prepends custom instructions to all AI calls

## RE:PLATFORM Tab Integration

- **Tab 1 (تحليل)**: After decompile → auto-creates edit session (`aSessId`) → shows CTA banner for Intel/Forensics
- **Tab 4 (استخبارات)** & **Tab 5 (طب شرعي)**: Use `iSess = eSess?.sessionId || aSessId` to auto-link with Tab 1/Tab 3
- **Session indicator**: Green dot on tab buttons when session active; file name shown in Intel/Forensics headers
- **Auto-analysis**: "تحليل تلقائي شامل" button runs Intel + Forensics sequentially

## Standalone RE:TOOLKIT Apps

- **Windows (Electron)**: `attached_assets/HAYO_AI_RE_TOOLKIT-Windows.zip` (8.7KB source) — requires `npm install && npm run build`
- **Android (Expo)**: Code at `/tmp/expo-app-code.js` (250 lines) — EAS build requires valid EXPO_ACCESS_TOKEN
- **Note**: EXPO_ACCESS_TOKEN is currently expired/invalid — user needs to regenerate from https://expo.dev/accounts/settings
