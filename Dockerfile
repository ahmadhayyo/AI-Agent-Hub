FROM node:20-slim AS base
RUN corepack enable && corepack prepare pnpm@9 --activate
WORKDIR /app

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.json ./
COPY lib/ ./lib/
COPY artifacts/api-server/package.json ./artifacts/api-server/
COPY artifacts/hayo-ai/package.json ./artifacts/hayo-ai/
COPY scripts/package.json ./scripts/

RUN pnpm install --no-frozen-lockfile --prod=false

COPY lib/ ./lib/
COPY artifacts/ ./artifacts/
COPY scripts/ ./scripts/
COPY shared/ ./shared/
COPY attached_assets/ ./attached_assets/

RUN pnpm --filter @workspace/hayo-ai run build
RUN pnpm --filter @workspace/api-server run build

EXPOSE 8080
ENV NODE_ENV=production
ENV PORT=8080

CMD ["node", "--enable-source-maps", "artifacts/api-server/dist/index.mjs"]
