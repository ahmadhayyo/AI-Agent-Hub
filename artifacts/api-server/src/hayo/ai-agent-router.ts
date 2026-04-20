import { z } from "zod";
import fs from "fs";
import path from "path";
import { router, ownerProcedure } from "./trpc";
import {
  executeAgentCommand,
  forgetAgentMemory,
  getAgentMemorySnapshot,
  pinAgentMemoryEntry,
} from "./services/ai-agent";

const PROJECT_ROOT = path.resolve(process.cwd(), "../..");

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "Unknown error";
}

function resolveSafe(fp: string): string | null {
  if (fp.startsWith("/")) return null;
  const resolved = path.resolve(path.join(PROJECT_ROOT, fp));
  const rel = path.relative(PROJECT_ROOT, resolved);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return null;
  return resolved;
}

export const aiAgentRouter = router({
  execute: ownerProcedure
    .input(z.object({
      command: z.string().min(2).max(5000),
      conversationHistory: z.array(z.object({
        role: z.enum(["user", "assistant"]),
        content: z.string(),
      })).default([]),
      sessionId: z.string().max(200).optional(),
      attachments: z.array(z.object({
        name: z.string().max(500),
        type: z.string().optional(),
        size: z.number().optional(),
        extractedText: z.string().max(2_000_000).optional(),
      })).default([]),
      autoExecute: z.boolean().default(false),
    }))
    .mutation(async ({ input, ctx }) => {
      return executeAgentCommand(
        input.command,
        input.conversationHistory,
        input.sessionId,
        input.attachments,
        input.autoExecute,
        ctx.user.id,
      );
    }),

  memorySnapshot: ownerProcedure
    .input(z.object({
      sessionId: z.string().max(200).optional(),
      maxItems: z.number().int().min(1).max(200).default(20),
    }))
    .query(({ input }) => {
      return getAgentMemorySnapshot(input.sessionId || "", input.maxItems);
    }),

  memoryAction: ownerProcedure
    .input(z.object({
      action: z.enum(["pin", "forget"]),
      sessionId: z.string().max(200).optional(),
      source: z.enum(["session", "project"]).optional(),
      at: z.string().optional(),
      commandHash: z.string().max(80).optional(),
      mode: z.enum(["session", "project", "pinned", "topic"]).optional(),
      topic: z.string().max(80).optional(),
    }))
    .mutation(({ input }) => {
      if (input.action === "pin") {
        if (!input.source || !input.at) {
          return { ok: false, changed: 0, message: "source و at مطلوبان لعملية pin" };
        }
        const result = pinAgentMemoryEntry({
          sessionId: input.sessionId,
          source: input.source,
          at: input.at,
          commandHash: input.commandHash,
        });
        return {
          ok: result.ok,
          changed: result.ok ? 1 : 0,
          message: result.message,
          pinnedCount: result.pinnedCount,
        };
      }

      const result = forgetAgentMemory({
        sessionId: input.sessionId,
        mode: input.mode || "session",
        at: input.at,
        commandHash: input.commandHash,
        topic: input.topic,
      });
      return {
        ok: result.ok,
        changed: result.removed,
        message: result.message,
      };
    }),

  applyOps: ownerProcedure
    .input(z.object({
      operations: z.array(z.object({
        action: z.enum(["create", "edit", "delete", "read"]),
        filePath: z.string().max(500),
        content: z.string().max(500000).optional(),
        description: z.string().max(500),
      })).max(20),
    }))
    .mutation(async ({ input }) => {
      const results: { action: string; filePath: string; success: boolean; error?: string }[] = [];

      for (const op of input.operations) {
        const abs = resolveSafe(op.filePath);
        if (!abs) {
          results.push({ action: op.action, filePath: op.filePath, success: false, error: "مسار خارج المشروع" });
          continue;
        }

        try {
          if (op.action === "create" || op.action === "edit") {
            const dir = path.dirname(abs);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(abs, op.content || "", "utf-8");
            results.push({ action: op.action, filePath: op.filePath, success: true });
          } else if (op.action === "delete") {
            if (fs.existsSync(abs)) {
              fs.unlinkSync(abs);
              results.push({ action: op.action, filePath: op.filePath, success: true });
            } else {
              results.push({ action: op.action, filePath: op.filePath, success: false, error: "الملف غير موجود" });
            }
          }
        } catch (e: unknown) {
          results.push({ action: op.action, filePath: op.filePath, success: false, error: getErrorMessage(e) });
        }
      }

      return { results };
    }),

  readFile: ownerProcedure
    .input(z.object({ filePath: z.string() }))
    .query(async ({ input }) => {
      const abs = resolveSafe(input.filePath);
      if (!abs) return { content: "", error: "مسار خارج المشروع" };
      if (!fs.existsSync(abs)) return { content: "", error: "الملف غير موجود" };

      try {
        const content = fs.readFileSync(abs, "utf-8");
        return { content, error: null };
      } catch (e: unknown) {
        return { content: "", error: getErrorMessage(e) };
      }
    }),

  projectTree: ownerProcedure.query(async () => {
    const FRONTEND = path.join(PROJECT_ROOT, "artifacts/hayo-ai/src");
    const BACKEND = path.join(PROJECT_ROOT, "artifacts/api-server/src/hayo");

    const IGNORED = new Set(["node_modules", ".git", "dist", "build", ".cache", ".local", ".config"]);
    const EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".css", ".json"]);

    function tree(dir: string, depth = 0, maxDepth = 3): string[] {
      if (depth > maxDepth || !fs.existsSync(dir)) return [];
      const results: string[] = [];
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true })
          .filter(e => !IGNORED.has(e.name) && !e.name.startsWith("."));
        for (const e of entries) {
          const full = path.join(dir, e.name);
          const rel = path.relative(PROJECT_ROOT, full);
          if (e.isDirectory()) {
            results.push(`📁 ${rel}/`);
            results.push(...tree(full, depth + 1, maxDepth));
          } else if (EXTS.has(path.extname(e.name))) {
            results.push(`📄 ${rel}`);
          }
        }
      } catch {}
      return results;
    }

    return {
      frontend: tree(FRONTEND),
      backend: tree(BACKEND),
    };
  }),
});
