/**
 * Reverse Engineer REST Routes — HAYO AI
 * Uses disk-backed uploads for large files.
 */

import { Router, type Request, type Response } from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import os from "os";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const uploadTmpDir = path.join(os.tmpdir(), "hayo_re_uploads");
if (!fs.existsSync(uploadTmpDir)) fs.mkdirSync(uploadTmpDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadTmpDir),
    filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
  }),
  limits: { fileSize: 500 * 1024 * 1024 }, // 500MB max
});

const router = Router();

// ── Helpers ──────────────────────────────────────────────────────
function readUploadedFile(file: Express.Multer.File): Buffer {
  if (file.buffer) return file.buffer;
  const buf = fs.readFileSync(file.path);
  try { fs.unlinkSync(file.path); } catch {}
  return buf;
}

async function commandAvailable(command: string, args: string[] = []): Promise<boolean> {
  try {
    await execFileAsync(command, args, {
      timeout: 5000,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function commandVersion(command: string, args: string[] = []): Promise<string | null> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: 10000,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
    const line = `${stdout ?? ""}\n${stderr ?? ""}`.split("\n").map((s) => s.trim()).find(Boolean);
    return line || null;
  } catch (error: any) {
    const line = `${error?.stdout ?? ""}\n${error?.stderr ?? ""}`.split("\n").map((s: string) => s.trim()).find(Boolean);
    return line || null;
  }
}

function ext(fileName: string): string {
  return (path.extname(fileName).slice(1) || "").toLowerCase();
}

function err(res: Response, e: unknown, fallback = "فشل العملية") {
  const msg = e instanceof Error ? e.message : String(e);
  console.error("[RE Route]", msg);
  res.status(500).json({ success: false, error: msg || fallback });
}

async function getService() {
  return import("./services/reverse-engineer.js");
}

// ── POST /api/reverse/decompile ────────────────────────────────
// Auto-detects file type by extension and dispatches to correct analyser.
router.post("/decompile", upload.single("file"), async (req: Request, res: Response) => {
  try {
    if (!req.file) { res.status(400).json({ error: "لم يُرفع أي ملف" }); return; }
    const originalname = req.file.originalname;
    const buffer = readUploadedFile(req.file);
    const svc = await getService();
    const fileExt = ext(originalname);

    let result;
    switch (fileExt) {
      case "apk":  result = await svc.decompileAPK(buffer, originalname); break;
      case "exe":
      case "dll":  result = await svc.analyzeEXE(buffer, originalname); break;
      case "ex4":  result = await svc.analyzeEX4(buffer, originalname); break;
      case "ex5":  result = await svc.analyzeEX5(buffer, originalname); break;
      case "elf":
      case "so":   result = await svc.analyzeELF(buffer, originalname); break;
      case "ipa":  result = await svc.analyzeIPA(buffer, originalname); break;
      case "jar":
      case "aar":  result = await svc.analyzeJAR(buffer, originalname, fileExt); break;
      case "wasm": result = await svc.analyzeWASM(buffer, originalname); break;
      case "dex":  result = await svc.analyzeDEX(buffer, originalname); break;
      default:
        res.status(400).json({ error: `نوع الملف غير مدعوم: .${fileExt}` });
        return;
    }

    const { zipBuffer, ...rest } = result;
    res.json({
      ...rest,
      hasZip: !!zipBuffer,
      zipBase64: zipBuffer ? zipBuffer.toString("base64") : undefined,
    });
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/analyze ──────────────────────────────────
// AI text analysis on already-decompiled code.
router.post("/analyze", async (req: Request, res: Response) => {
  try {
    const { code, fileName, analysisType } = req.body as {
      code: string; fileName: string;
      analysisType: "explain" | "security" | "logic" | "full";
    };
    if (!code || !fileName || !analysisType) {
      res.status(400).json({ error: "code, fileName, analysisType مطلوبة" }); return;
    }
    const { analyzeWithAI } = await getService();
    const analysis = await analyzeWithAI(code, fileName, analysisType);
    res.json({ success: true, analysis });
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/clone ────────────────────────────────────
// Clone / patch app: FormData with "file" + JSON options.
router.post("/clone", upload.single("file"), async (req: Request, res: Response) => {
  try {
    if (!req.file) { res.status(400).json({ error: "لم يُرفع أي ملف" }); return; }
    const originalname = req.file.originalname;
    const buffer = readUploadedFile(req.file);
    const options = {
      removeAds:           req.body.removeAds           === "true",
      unlockPremium:       req.body.unlockPremium       === "true",
      removeTracking:      req.body.removeTracking      === "true",
      removeLicenseCheck:  req.body.removeLicenseCheck  === "true",
      changeAppName:       req.body.changeAppName        || undefined,
      changePackageName:   req.body.changePackageName   || undefined,
      customInstructions:  req.body.customInstructions  || undefined,
    };
    const { cloneApp } = await getService();
    const result = await cloneApp(buffer, originalname, options);
    const { apkBuffer, ...rest } = result;
    res.json({
      ...rest,
      apkBase64: apkBuffer ? apkBuffer.toString("base64") : undefined,
    });
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/decompile-for-edit ──────────────────────
// Decompile any supported file and open a mutable edit session.
router.post("/decompile-for-edit", upload.single("file"), async (req: Request, res: Response) => {
  try {
    if (!req.file) { res.status(400).json({ error: "لم يُرفع أي ملف" }); return; }
    const originalname = req.file.originalname;
    const buffer = readUploadedFile(req.file);
    const { decompileFileForEdit } = await getService();
    const result = await decompileFileForEdit(buffer, originalname);
    res.json(result);
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/save-edit ───────────────────────────────
router.post("/save-edit", async (req: Request, res: Response) => {
  try {
    const { sessionId, filePath, content } = req.body as {
      sessionId: string; filePath: string; content: string;
    };
    if (!sessionId || !filePath || content === undefined) {
      res.status(400).json({ error: "sessionId, filePath, content مطلوبة" }); return;
    }
    const { saveFileEdit } = await getService();
    res.json(saveFileEdit(sessionId, filePath, content));
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/file-content ────────────────────────────
router.post("/file-content", async (req: Request, res: Response) => {
  try {
    const { sessionId, filePath } = req.body as { sessionId: string; filePath: string };
    if (!sessionId || !filePath) {
      res.status(400).json({ error: "sessionId, filePath مطلوبة" }); return;
    }
    const { readSessionFileContent } = await getService();
    res.json(readSessionFileContent(sessionId, filePath));
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/ai-modify ───────────────────────────────
router.post("/ai-modify", async (req: Request, res: Response) => {
  try {
    const { code, instruction, fileName } = req.body as {
      code: string; instruction: string; fileName: string;
    };
    if (!code || !instruction || !fileName) {
      res.status(400).json({ error: "code, instruction, fileName مطلوبة" }); return;
    }
    const { aiModifyCode } = await getService();
    res.json(await aiModifyCode(code, instruction, fileName));
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/ai-search ───────────────────────────────
router.post("/ai-search", async (req: Request, res: Response) => {
  try {
    const { sessionId, query } = req.body as { sessionId: string; query: string };
    if (!sessionId || !query) {
      res.status(400).json({ error: "sessionId, query مطلوبة" }); return;
    }
    const { aiSearchFiles } = await getService();
    res.json(await aiSearchFiles(sessionId, query));
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/ai-smart-modify ────────────────────────
router.post("/ai-smart-modify", async (req: Request, res: Response) => {
  try {
    const { sessionId, instruction } = req.body as { sessionId: string; instruction: string };
    if (!sessionId || !instruction) {
      res.status(400).json({ error: "sessionId, instruction مطلوبة" }); return;
    }
    const { aiSmartModify } = await getService();
    res.json(await aiSmartModify(sessionId, instruction));
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/rebuild ─────────────────────────────────
// Returns the rebuilt APK as raw binary (application/octet-stream).
router.post("/rebuild", async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.body as { sessionId: string };
    if (!sessionId) { res.status(400).json({ error: "sessionId مطلوب" }); return; }
    const { rebuildAPK } = await getService();
    const result = await rebuildAPK(sessionId);
    if (!result.success || !result.apkBuffer) {
      res.status(500).json({ success: false, error: result.error || "فشل إعادة البناء" });
      return;
    }
    res.setHeader("Content-Type", "application/vnd.android.package-archive");
    res.setHeader("Content-Disposition", "attachment; filename=\"rebuilt.apk\"");
    res.setHeader("Content-Length", result.apkBuffer.length);
    res.send(result.apkBuffer);
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/intelligence-report ────────────────────
router.post("/intelligence-report", async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.body as { sessionId: string };
    if (!sessionId) { res.status(400).json({ error: "sessionId مطلوب" }); return; }
    const { generateIntelligenceReport } = await getService();
    res.json(await generateIntelligenceReport(sessionId));
  } catch (e) { err(res, e); }
});

// ── POST /api/reverse/regex-search ───────────────────────────
router.post("/regex-search", async (req: Request, res: Response) => {
  try {
    const { sessionId, pattern, category } = req.body as {
      sessionId: string; pattern: string; category?: string;
    };
    if (!sessionId || !pattern) {
      res.status(400).json({ error: "sessionId, pattern مطلوبة" }); return;
    }
    const { regexSearchFiles } = await getService();
    try {
      const results = regexSearchFiles(sessionId, pattern, category);
      res.json({ success: true, results });
    } catch (innerErr: any) {
      res.status(400).json({ success: false, error: innerErr.message });
    }
  } catch (e) { err(res, e); }
});

// ── GET /api/reverse/session/:sessionId ──────────────────────
router.get("/session/:sessionId", async (req: Request, res: Response) => {
  try {
    const { getSessionInfo } = await getService();
    const sessionId = typeof req.params.sessionId === "string" ? req.params.sessionId : "";
    const info = getSessionInfo(sessionId);
    if (!info.exists) { res.status(404).json({ error: "الجلسة غير موجودة" }); return; }
    res.json(info);
  } catch (e) { err(res, e); }
});

// ── GET /api/reverse/check-tools ─────────────────────────────
router.get("/check-tools", async (_req: Request, res: Response) => {
  try {
    const { findApkTool, isJavaAvailable, isApkToolAvailable } = await getService();
    const jadxVersion = await commandVersion("/home/runner/jadx/bin/jadx", ["--version"])
      ?? ((await commandAvailable("jadx", ["--version"])) ? "installed" : null);
    const apkToolVersion = await commandVersion("java", ["-jar", "/home/runner/apktool/apktool.jar", "--version"]);
    const jarsignerAvailable = await commandAvailable("jarsigner");
    const keytoolAvailable = await commandAvailable("keytool", ["-help"]);
    const wasm2watAvailable = await commandAvailable("wasm2wat", ["--version"]);
    const readelfAvailable = await commandAvailable("readelf", ["--version"]);
    const objdumpAvailable = await commandAvailable("objdump", ["--version"]);
    const stringsAvailable = await commandAvailable("strings", ["--version"]);
    const xxdAvailable = await commandAvailable("xxd", ["--version"]);

    res.json({
      apkToolPath: await findApkTool(),
      javaAvailable: await isJavaAvailable(),
      apkToolAvailable: await isApkToolAvailable(),
      jadxVersion,
      apkToolVersion,
      jarsignerAvailable,
      keytoolAvailable,
      keystoreExists: fs.existsSync("/home/runner/debug.keystore"),
      wasm2watAvailable,
      readelfAvailable,
      objdumpAvailable,
      stringsAvailable,
      xxdAvailable,
    });
  } catch (e) { err(res, e); }
});

export default router;
