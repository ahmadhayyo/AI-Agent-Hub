/**
 * Reverse Engineer tRPC Router — HAYO AI
 * Exposes all 27 exports from reverse-engineer.ts as API endpoints.
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { router, protectedProcedure } from "./trpc";

// ── Helpers ──────────────────────────────────────────────────────
function base64ToBuffer(b64: string): Buffer {
  return Buffer.from(b64, "base64");
}

// ── Router ───────────────────────────────────────────────────────
export const reverseEngineerRouter = router({

  // ── 1. Decompile APK ────────────────────────────────────────────
  decompileAPK: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { decompileAPK } = await import("./services/reverse-engineer.js");
      const result = await decompileAPK(base64ToBuffer(input.fileBase64), input.fileName);
      // Strip binary zipBuffer from JSON response — expose separately
      const { zipBuffer, ...rest } = result;
      return {
        ...rest,
        hasZip: !!zipBuffer,
        zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined,
      };
    }),

  // ── 2. Analyze EXE / DLL ────────────────────────────────────────
  analyzeEXE: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { analyzeEXE } = await import("./services/reverse-engineer.js");
      const result = await analyzeEXE(base64ToBuffer(input.fileBase64), input.fileName);
      const { zipBuffer, ...rest } = result;
      return { ...rest, hasZip: !!zipBuffer, zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined };
    }),

  // ── 3. Analyze EX4 (MetaTrader 4) ──────────────────────────────
  analyzeEX4: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { analyzeEX4 } = await import("./services/reverse-engineer.js");
      const result = await analyzeEX4(base64ToBuffer(input.fileBase64), input.fileName);
      const { zipBuffer, ...rest } = result;
      return { ...rest, hasZip: !!zipBuffer, zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined };
    }),

  // ── 4. Analyze EX5 (MetaTrader 5) ──────────────────────────────
  analyzeEX5: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { analyzeEX5 } = await import("./services/reverse-engineer.js");
      const result = await analyzeEX5(base64ToBuffer(input.fileBase64), input.fileName);
      const { zipBuffer, ...rest } = result;
      return { ...rest, hasZip: !!zipBuffer, zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined };
    }),

  // ── 5. Analyze ELF (Linux binary / .so) ────────────────────────
  analyzeELF: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { analyzeELF } = await import("./services/reverse-engineer.js");
      const result = await analyzeELF(base64ToBuffer(input.fileBase64), input.fileName);
      const { zipBuffer, ...rest } = result;
      return { ...rest, hasZip: !!zipBuffer, zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined };
    }),

  // ── 6. Analyze IPA (iOS App) ────────────────────────────────────
  analyzeIPA: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { analyzeIPA } = await import("./services/reverse-engineer.js");
      const result = await analyzeIPA(base64ToBuffer(input.fileBase64), input.fileName);
      const { zipBuffer, ...rest } = result;
      return { ...rest, hasZip: !!zipBuffer, zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined };
    }),

  // ── 7. Analyze JAR / AAR ────────────────────────────────────────
  analyzeJAR: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
      fileExt: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { analyzeJAR } = await import("./services/reverse-engineer.js");
      const result = await analyzeJAR(base64ToBuffer(input.fileBase64), input.fileName, input.fileExt);
      const { zipBuffer, ...rest } = result;
      return { ...rest, hasZip: !!zipBuffer, zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined };
    }),

  // ── 8. Analyze WASM ─────────────────────────────────────────────
  analyzeWASM: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { analyzeWASM } = await import("./services/reverse-engineer.js");
      const result = await analyzeWASM(base64ToBuffer(input.fileBase64), input.fileName);
      const { zipBuffer, ...rest } = result;
      return { ...rest, hasZip: !!zipBuffer, zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined };
    }),

  // ── 9. Analyze DEX (Dalvik bytecode) ────────────────────────────
  analyzeDEX: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { analyzeDEX } = await import("./services/reverse-engineer.js");
      const result = await analyzeDEX(base64ToBuffer(input.fileBase64), input.fileName);
      const { zipBuffer, ...rest } = result;
      return { ...rest, hasZip: !!zipBuffer, zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined };
    }),

  // ── 10. AI Code Analysis ────────────────────────────────────────
  analyzeWithAI: protectedProcedure
    .input(z.object({
      code: z.string(),
      fileName: z.string(),
      analysisType: z.enum(["explain", "security", "logic", "full"]),
    }))
    .mutation(async ({ input }) => {
      const { analyzeWithAI } = await import("./services/reverse-engineer.js");
      const result = await analyzeWithAI(input.code, input.fileName, input.analysisType);
      return { analysis: result };
    }),

  // ── 11. Scan Vulnerabilities ────────────────────────────────────
  scanVulnerabilities: protectedProcedure
    .input(z.object({
      files: z.array(z.object({
        path: z.string(),
        name: z.string(),
        extension: z.string(),
        size: z.number(),
        content: z.string().optional(),
        isBinary: z.boolean(),
      })),
      fileType: z.string(),
      extraStrings: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { scanVulnerabilities } = await import("./services/reverse-engineer.js");
      const findings = scanVulnerabilities(input.files as any, input.fileType, input.extraStrings);
      return { findings };
    }),

  checkTools: protectedProcedure
    .query(async () => {
      const { getToolStatus } = await import("./services/reverse-engineer.js");
      return getToolStatus();
    }),

  // ── 13. Decompile APK for Edit Session ──────────────────────────
  decompileAPKForEdit: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { decompileAPKForEdit } = await import("./services/reverse-engineer.js");
      const result = await decompileAPKForEdit(base64ToBuffer(input.fileBase64));
      return result;
    }),

  // ── 14. Decompile Any File for Edit Session ──────────────────────
  decompileFileForEdit: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { decompileFileForEdit } = await import("./services/reverse-engineer.js");
      const result = await decompileFileForEdit(base64ToBuffer(input.fileBase64), input.fileName);
      return result;
    }),

  // ── 15. Get Session Info ────────────────────────────────────────
  getSessionInfo: protectedProcedure
    .input(z.object({ sessionId: z.string() }))
    .query(async ({ input }) => {
      const { getSessionInfo } = await import("./services/reverse-engineer.js");
      const info = getSessionInfo(input.sessionId);
      return info;
    }),

  // ── 16. Read Session File Content ───────────────────────────────
  readSessionFileContent: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      filePath: z.string(),
    }))
    .query(async ({ input }) => {
      const { readSessionFileContent } = await import("./services/reverse-engineer.js");
      return readSessionFileContent(input.sessionId, input.filePath);
    }),

  // ── 17. Save File Edit ──────────────────────────────────────────
  saveFileEdit: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      filePath: z.string(),
      newContent: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { saveFileEdit } = await import("./services/reverse-engineer.js");
      return saveFileEdit(input.sessionId, input.filePath, input.newContent);
    }),

  // ── 18. Revert File to Original ─────────────────────────────────
  revertFile: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      filePath: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { revertFile } = await import("./services/reverse-engineer.js");
      return revertFile(input.sessionId, input.filePath);
    }),

  // ── 19. AI Modify Code ──────────────────────────────────────────
  aiModifyCode: protectedProcedure
    .input(z.object({
      code: z.string(),
      instruction: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { aiModifyCode } = await import("./services/reverse-engineer.js");
      return aiModifyCode(input.code, input.instruction, input.fileName);
    }),

  // ── 20. AI Search Files in Session ──────────────────────────────
  aiSearchFiles: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      query: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { aiSearchFiles } = await import("./services/reverse-engineer.js");
      return aiSearchFiles(input.sessionId, input.query);
    }),

  // ── 21. Rebuild APK from Session ────────────────────────────────
  rebuildAPK: protectedProcedure
    .input(z.object({ sessionId: z.string() }))
    .mutation(async ({ input }) => {
      const { rebuildAPK } = await import("./services/reverse-engineer.js");
      const result = await rebuildAPK(input.sessionId);
      if (result.apkBuffer) {
        return {
          success: result.success,
          signed: result.signed,
          error: result.error,
          apkBase64: result.apkBuffer.toString("base64"),
        };
      }
      return { success: result.success, signed: result.signed, error: result.error, apkBase64: undefined };
    }),

  // ── 22. AI Smart Modify (bulk session edit) ──────────────────────
  aiSmartModify: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      instruction: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { aiSmartModify } = await import("./services/reverse-engineer.js");
      return aiSmartModify(input.sessionId, input.instruction);
    }),

  // ── 23. Clone App (modify + repackage) ──────────────────────────
  cloneApp: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
      options: z.object({
        removeAds: z.boolean().default(false),
        unlockPremium: z.boolean().default(false),
        removeTracking: z.boolean().default(false),
        removeLicenseCheck: z.boolean().default(false),
        changeAppName: z.string().optional(),
        changePackageName: z.string().optional(),
        customInstructions: z.string().optional(),
      }),
    }))
    .mutation(async ({ input }) => {
      const { cloneApp } = await import("./services/reverse-engineer.js");
      const result = await cloneApp(base64ToBuffer(input.fileBase64), input.fileName, input.options);
      if (result.apkBuffer) {
        return {
          success: result.success,
          signed: result.signed,
          modifications: result.modifications,
          error: result.error,
          apkBase64: result.apkBuffer.toString("base64"),
        };
      }
      return { success: result.success, signed: result.signed, modifications: result.modifications, error: result.error, apkBase64: undefined };
    }),

  // ── 24. Generate Intelligence Report ────────────────────────────
  generateIntelligenceReport: protectedProcedure
    .input(z.object({ sessionId: z.string() }))
    .mutation(async ({ input }) => {
      const { generateIntelligenceReport } = await import("./services/reverse-engineer.js");
      return generateIntelligenceReport(input.sessionId);
    }),

  // ── 25. Regex Search Files in Session ───────────────────────────
  regexSearchFiles: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      pattern: z.string(),
      category: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { regexSearchFiles } = await import("./services/reverse-engineer.js");
      try {
        const results = regexSearchFiles(input.sessionId, input.pattern, input.category);
        return { results };
      } catch (err: any) {
        throw new TRPCError({ code: "BAD_REQUEST", message: err.message });
      }
    }),

  // ── 26. Auto-detect file type and dispatch ───────────────────────
  analyzeAuto: protectedProcedure
    .input(z.object({
      fileBase64: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const ext = input.fileName.split(".").pop()?.toLowerCase() ?? "";
      const {
        decompileAPK, analyzeEXE, analyzeEX4, analyzeEX5,
        analyzeELF, analyzeIPA, analyzeJAR, analyzeWASM, analyzeDEX,
      } = await import("./services/reverse-engineer.js");

      const buf = base64ToBuffer(input.fileBase64);
      let result;

      switch (ext) {
        case "apk":  result = await decompileAPK(buf, input.fileName); break;
        case "exe":
        case "dll":  result = await analyzeEXE(buf, input.fileName); break;
        case "ex4":  result = await analyzeEX4(buf, input.fileName); break;
        case "ex5":  result = await analyzeEX5(buf, input.fileName); break;
        case "elf":
        case "so":   result = await analyzeELF(buf, input.fileName); break;
        case "ipa":  result = await analyzeIPA(buf, input.fileName); break;
        case "jar":
        case "aar":  result = await analyzeJAR(buf, input.fileName, ext); break;
        case "wasm": result = await analyzeWASM(buf, input.fileName); break;
        case "dex":  result = await analyzeDEX(buf, input.fileName); break;
        default:
          throw new TRPCError({ code: "BAD_REQUEST", message: `نوع الملف غير مدعوم: .${ext}` });
      }

      const { zipBuffer, ...rest } = result;
      return { ...rest, hasZip: !!zipBuffer, zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined };
    }),

  // ── 27. List Edit Session Files ──────────────────────────────────
  listSessionFiles: protectedProcedure
    .input(z.object({ sessionId: z.string() }))
    .query(async ({ input }) => {
      const { getSessionInfo } = await import("./services/reverse-engineer.js");
      const info = getSessionInfo(input.sessionId);
      if (!info.exists) throw new TRPCError({ code: "NOT_FOUND", message: "الجلسة غير موجودة" });
      return info;
    }),
});

export type ReverseEngineerRouter = typeof reverseEngineerRouter;
