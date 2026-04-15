# AGENTS.md

## Cursor Cloud specific instructions

### Services overview

| Service | Command | Port | Notes |
|---|---|---|---|
| **API Server** | `pnpm --filter @workspace/api-server run dev` | 8080 | Express + tRPC backend. Requires `DATABASE_URL`, `SESSION_SECRET` env vars. |
| **Frontend** | `pnpm --filter @workspace/hayo-ai run dev` | 23836 | React + Vite. Proxies `/api` → `localhost:8080`. Set `PORT=23836`. |

### PostgreSQL

PostgreSQL 16 must be running on `localhost:5432`. Start it with:

```bash
sudo pg_ctlcluster 16 main start
```

Database name: `hayo_ai`. Connection string format: `postgresql://ubuntu:devpass@localhost:5432/hayo_ai`.

After starting PostgreSQL, push the schema:

```bash
DATABASE_URL=postgresql://ubuntu:devpass@localhost:5432/hayo_ai pnpm --filter @workspace/db push
```

### Environment variables

The API server reads env vars directly (not from `.env` files automatically). Export them in the shell before running:

- `DATABASE_URL` — PostgreSQL connection string (required)
- `SESSION_SECRET` — any random string (required)
- `PORT=8080` — API server port
- `NODE_ENV=development`

AI provider keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, `GOOGLE_API_KEY3`) are optional for basic startup but required for AI features.

### Build system

- The API server uses **esbuild** (not tsc) for building — TypeScript errors in `tsc --noEmit` do not block the server from running. Pre-existing TS errors exist in `src/telegram/bot.ts`.
- The `dev` script for api-server runs `build` then `start` (no watch mode). Restart manually after code changes.
- The frontend Vite dev server has HMR.

### Linting / Code quality

- No ESLint configured. The project uses `prettier` (root devDependency) for formatting.
- Typecheck: `pnpm run typecheck` (has pre-existing errors in telegram bot code).
- Format check: `npx prettier --check .`

### Owner / admin account

On first startup, the API server seeds an owner account: `Fmf0038@gmail.com` / `6088amhA+` (role: admin). Admin panel at `/admin`.

### Gotchas

- `pnpm db:push` does not exist as a root script. Use `pnpm --filter @workspace/db push` instead.
- The `pnpm-workspace.yaml` has `onlyBuiltDependencies` configured — no need to run `pnpm approve-builds`.
- `pnpm install` may warn about ignored build scripts for `tesseract.js` — this is harmless and does not affect functionality.
- The Vite config conditionally loads Replit-specific plugins only when `REPL_ID` env var is set, so they are safely skipped outside Replit.
