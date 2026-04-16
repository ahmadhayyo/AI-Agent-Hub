# AGENTS.md

## Cursor Cloud specific instructions

### Overview
HAYO AI is a full-stack TypeScript monorepo (pnpm workspaces) with an Express+tRPC backend and React+Vite frontend. See `CLAUDE.md` for architecture details and key commands (`pnpm dev`, `pnpm build`, `pnpm db:push`).

### PostgreSQL
- PostgreSQL 16 must be running locally. Start with: `sudo pg_ctlcluster 16 main start`
- Database: `hayo_ai`, user: `ubuntu`, password: `devpass`
- `DATABASE_URL=postgresql://ubuntu:devpass@localhost:5432/hayo_ai`
- Push schema changes: `DATABASE_URL="postgresql://ubuntu:devpass@localhost:5432/hayo_ai" pnpm --filter @workspace/db run push`

### Environment Variables
The app does **not** use `dotenv` — all env vars must be exported in the shell before starting services. Key required vars:
- `DATABASE_URL` — PostgreSQL connection string
- `SESSION_SECRET` — any random string
- `PORT=8080` — for the API server
- `NODE_ENV=development`

A `.env` file exists at the repo root for reference but is not auto-loaded.

### Starting Services
1. **API Server** (port 8080): `DATABASE_URL="postgresql://ubuntu:devpass@localhost:5432/hayo_ai" SESSION_SECRET="dev-session-secret" PORT=8080 NODE_ENV=development pnpm --filter @workspace/api-server run dev`
2. **Frontend** (port 23836): `pnpm --filter @workspace/hayo-ai run dev`

The frontend proxies `/api` requests to `http://localhost:8080`.

### Build & Typecheck
- `pnpm --filter @workspace/api-server run build` — esbuild bundle (succeeds)
- `pnpm --filter @workspace/hayo-ai run build` — Vite production build (succeeds)
- `pnpm run typecheck` — has pre-existing TS errors in `telegram/bot.ts` and `TradingAnalysis.tsx`; these are known and do not block builds

### Linting
- No ESLint configured. Prettier is available: `pnpm exec prettier --check <file>`

### Gotchas
- The `preinstall` script in root `package.json` enforces pnpm — do not use npm or yarn.
- `pnpm-workspace.yaml` has `onlyBuiltDependencies` allowlist and `minimumReleaseAge: 1440` for supply-chain protection. A warning about `tesseract.js` build scripts is cosmetic.
- Telegram bots are gracefully disabled when their tokens are not set.
- AI features (chat, agents, analysis) require at least one AI provider API key (`DEEPSEEK_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GOOGLE_API_KEY3`).

### Railway Deployment
- Project: **steadfast-compassion**, Service: **hayo-api** (port 8080), DB: **local-postgres**
- Public URL: `https://hayo-api-production.up.railway.app`
- `railway.toml` defines build/deploy config; the `startCommand` overrides Docker CMD — always update both if changing the startup sequence.
- Use `RAILWAY_TOKEN="$RAILWAY_API_TOKEN" railway <command>` for CLI access (project-scoped token). For commands requiring project/env flags: `-p "3b067079-0211-4166-925b-980f3d02c0f6" -e production`.
- Check service status: `railway service status --all`
- View logs: `railway logs --service hayo-api`
- View env vars: `railway variables --service hayo-api --json`
