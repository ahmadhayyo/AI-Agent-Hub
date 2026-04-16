#!/bin/sh
set -e

echo "[Railway] Pushing database schema..."
pnpm --filter @workspace/db run push || echo "[Railway] WARNING: db push failed (may already be up to date)"

echo "[Railway] Starting server..."
exec node --enable-source-maps artifacts/api-server/dist/index.mjs
