# AGENTS.md

## Cursor Cloud specific instructions

### Overview

HAYO AI is a full-stack TypeScript monorepo (pnpm workspaces) with two main services:

| Service | Package | Dev Port | Run Command |
|---------|---------|----------|-------------|
| API Server | `@workspace/api-server` | 8080 | `pnpm --filter @workspace/api-server run dev` |
| Frontend | `@workspace/hayo-ai` | 23836 | `PORT=23836 pnpm --filter @workspace/hayo-ai run dev` |

### Prerequisites

- **PostgreSQL** must be running locally. Create a database and set `DATABASE_URL`.
- Required env vars: `DATABASE_URL`, `SESSION_SECRET`, `PORT=8080`, `NODE_ENV=development`.
- After PostgreSQL is available, push the schema: `pnpm --filter @workspace/db run push`.

### Running services

1. Start PostgreSQL: `sudo pg_ctlcluster 16 main start`
2. Start API server: `DATABASE_URL="postgresql://hayo:hayo123@localhost:5432/hayo_ai" SESSION_SECRET="dev-session-secret-for-local-development-only" PORT=8080 NODE_ENV=development pnpm --filter @workspace/api-server run dev`
3. Start frontend: `PORT=23836 pnpm --filter @workspace/hayo-ai run dev`

The frontend Vite dev server proxies `/api` requests to `localhost:8080`.

### Build and typecheck

- **Build backend**: `pnpm --filter @workspace/api-server run build` (uses esbuild, always succeeds)
- **Build frontend**: `pnpm --filter @workspace/hayo-ai run build` (uses Vite)
- **Typecheck**: `pnpm run typecheck` — expect pre-existing TS errors in `telegram/bot.ts` and `hayo/router.ts`; these are known issues noted in `SETUP_GUIDE.md` and do not affect runtime since esbuild skips type checking.

### Gotchas

- There is no root `pnpm dev` script. Each service must be started individually with `--filter`.
- The API server `dev` script does `build && start` (not hot-reload). After code changes, restart the server.
- The frontend uses Vite HMR and picks up changes automatically.
- No ESLint config exists. The project has `prettier` in devDependencies but no `.prettierrc` — use default Prettier settings.
- AI features (chat, code analysis) require API keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.) which are optional for basic app functionality.
- Admin panel: navigate to `/admin`, password is `6088amhA+`.
- The `pnpm install` warning about `tesseract.js` build scripts is expected and can be ignored — OCR works without the native build.
