# HAYO AI - Project Context

## Architecture
- Full-stack TypeScript monorepo (pnpm workspaces)
- Frontend: React + Vite (artifacts/hayo-ai/)
- Backend: Express + tRPC (artifacts/api-server/)
- Database: Drizzle ORM with PostgreSQL (lib/db/)
- Shared types: shared/ directory

## Key Sections
1. **App Builder** (منشئ التطبيقات): Generates React Native code and builds Android APKs via Expo EAS Build
   - Service: artifacts/api-server/src/hayo/services/eas-builder.ts
   - Router: artifacts/api-server/src/hayo/router.ts (builds section ~line 2452)
   - Frontend: artifacts/hayo-ai/src/pages/AppBuilder.tsx

2. **Reverse Engineering** (الهندسة العكسية): Code analysis and reverse engineering tools
   - Frontend: artifacts/hayo-ai/src/pages/CodeAgent.tsx

## Important Config
- Expo Project ID: 4dfec6e4-f48a-456a-a168-e70849564e09
- Expo Slug: hayo--04b69591
- EXPO_ACCESS_TOKEN must be set in environment

## Commands
- Dev: pnpm dev
- Build: pnpm build
- Database: pnpm db:push
