#!/usr/bin/env sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

export NODE_ENV="${NODE_ENV:-production}"
export PORT="${PORT:-8080}"

echo "[railway] installing dependencies with pnpm..."
pnpm install --frozen-lockfile

echo "[railway] building frontend..."
pnpm --filter @workspace/hayo-ai run build

echo "[railway] building backend..."
pnpm --filter @workspace/api-server run build

echo "[railway] starting backend on port ${PORT}..."
exec pnpm --filter @workspace/api-server run start
