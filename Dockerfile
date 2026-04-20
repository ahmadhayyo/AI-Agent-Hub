FROM node:20-slim AS base

RUN corepack enable && corepack prepare pnpm@9 --activate

# ── Install Reverse Engineering Tools ──────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk-headless \
    binutils \
    xxd \
    wabt \
    wget \
    unzip \
    zip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create /home/runner directory structure (Replit-compatible paths)
RUN mkdir -p /home/runner/jadx/bin /home/runner/apktool

# Download JADX (latest stable)
RUN wget -q "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip" -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /home/runner/jadx \
    && chmod +x /home/runner/jadx/bin/jadx /home/runner/jadx/bin/jadx-gui \
    && ln -sf /home/runner/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip

# Download APKTool
RUN wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.10.0.jar" -O /home/runner/apktool/apktool.jar \
    && ln -sf /home/runner/apktool/apktool.jar /usr/local/lib/apktool.jar \
    && printf '#!/bin/bash\njava -jar /home/runner/apktool/apktool.jar "$@"' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# Generate debug keystore for APK signing
RUN keytool -genkeypair -v \
    -keystore /home/runner/debug.keystore \
    -storepass android \
    -alias androiddebugkey \
    -keypass android \
    -keyalg RSA -keysize 2048 -validity 36500 \
    -dname "CN=Android Debug,O=Android,C=US"

# ── Node.js App Build ──────────────────────────────────────────
WORKDIR /app

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.json tsconfig.base.json ./
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
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

CMD ["node", "--enable-source-maps", "artifacts/api-server/dist/index.mjs"]
