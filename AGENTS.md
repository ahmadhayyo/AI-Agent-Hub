# AGENTS.md

## Cursor Cloud specific instructions

### Overview
Full-stack TypeScript monorepo (pnpm workspaces). See `CLAUDE.md` for architecture details and `SETUP_GUIDE.md` for environment setup instructions.

### Running services
- **Backend**: `DATABASE_URL=... SESSION_SECRET=... pnpm --filter @workspace/api-server dev` (port 8080). The `dev` script builds with esbuild then starts node.
- **Frontend**: `pnpm --filter @workspace/hayo-ai dev` (Vite on port 23836, proxies `/api` → `http://localhost:8080`).
- Both must run simultaneously for the app to work.

### Database
- PostgreSQL required. Set `DATABASE_URL` env var before starting backend.
- Push schema: `pnpm --filter @workspace/db push` (needs `DATABASE_URL` in env, not just `.env` file).
- The `.env` file is NOT auto-loaded by the backend — export `DATABASE_URL` and `SESSION_SECRET` as shell env vars.

### Gotchas
- The `preinstall` script rejects npm/yarn — always use `pnpm`.
- TypeScript errors are expected (legacy schema issues) — the server builds with esbuild directly, ignoring type errors.
- Telegram bots are disabled without `TELEGRAM_BOT_TOKEN` — this is normal for local dev.
- The reverse engineering tools page (`/reverse`) checks for system binaries (Java, readelf, objdump, strings, xxd, wasm2wat, JADX, APKTool). JADX and APKTool are auto-downloaded on first use if Java is available.
