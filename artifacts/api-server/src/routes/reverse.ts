import { Router, type Request, type Response } from "express";
import multer from "multer";
import {
  decompileAPK,
  analyzeEXE,
  analyzeELF,
  analyzeIPA,
  analyzeJAR,
  analyzeEX4,
  analyzeEX5,
  analyzeWASM,
  analyzeDEX,
  analyzeWithAI,
  decompileFileForEdit,
  getSessionInfo,
  readSessionFileContent,
  saveFileEdit,
  aiModifyCode,
  aiSearchFiles,
  aiSmartModify,
  rebuildAPK,
  cloneApp,
  generateIntelligenceReport,
  regexSearchFiles,
  revertFile,
  editSessions,
  readDirRecursive,
  analyzeCertificate,
  analyzePermissionRisk,
  extractNetworkEndpoints,
  detectObfuscation,
  detectMalwarePatterns,
  aiVulnerabilityScan,
  aiDecompileSmali,
  extractStringsFromBinary,
  parseDEXHeader,
  parsePEHeaderDetailed,
  isJavaAvailable,
  isApkToolAvailable,
  findApkTool,
  getToolStatus,
  decodeStringsInFiles,
  crossReference,
  buildClassHierarchy,
  diffAPKs,
  analyzeDataFlow,
  methodSignatureSearch,
  generateForensicReport,
} from "../hayo/services/reverse-engineer.js";
import { callPowerAI } from "../hayo/providers.js";
import path from "path";
import fs from "fs";
import os from "os";
import { spawn } from "child_process";

const router = Router();

const tmpUploadDir = path.join(os.tmpdir(), "hayo_re_uploads");
if (!fs.existsSync(tmpUploadDir)) fs.mkdirSync(tmpUploadDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, tmpUploadDir),
    filename: (_req, _file, cb) => cb(null, `${Date.now()}-${_file.originalname}`)
  }),
  limits: { fileSize: 500 * 1024 * 1024 },
});

function readUploadedFile(file: Express.Multer.File): Buffer {
  if (file.buffer) return file.buffer;
  const buf = fs.readFileSync(file.path);
  try { fs.unlinkSync(file.path); } catch {}
  return buf;
}

function extendTimeout(req: Request, res: Response, ms = 300_000) {
  req.setTimeout(ms);
  res.setTimeout(ms);
}

async function decompileByType(buffer: Buffer, fileName: string) {
  const ext = fileName.split(".").pop()?.toLowerCase() || "";
  switch (ext) {
    case "apk":               return decompileAPK(buffer, fileName);
    case "exe":
    case "dll":               return analyzeEXE(buffer, fileName);
    case "elf":
    case "so":
    case "bin":               return analyzeELF(buffer, fileName);
    case "ipa":               return analyzeIPA(buffer, fileName);
    case "jar":
    case "aar":
    case "class":             return analyzeJAR(buffer, fileName);
    case "ex4":               return analyzeEX4(buffer, fileName);
    case "ex5":               return analyzeEX5(buffer, fileName);
    case "wasm":              return analyzeWASM(buffer, fileName);
    case "dex":               return analyzeDEX(buffer, fileName);
    default:                  return decompileAPK(buffer, fileName);
  }
}

function getSessionFiles(sessionId: string) {
  const session = editSessions.get(sessionId);
  if (!session) return null;
  const files: Array<{ path: string; name: string; extension: string; size: number; content: string; isBinary: boolean }> = [];
  const allFiles = readDirRecursive(session.decompDir);
  for (const fp of allFiles) {
    try {
      const stat = fs.statSync(fp);
      if (stat.size < 500000) {
        const relPath = path.relative(session.decompDir, fp);
        files.push({
          path: relPath,
          name: path.basename(fp),
          extension: path.extname(fp).slice(1).toLowerCase(),
          size: stat.size,
          content: fs.readFileSync(fp, "utf-8"),
          isBinary: false,
        });
      }
    } catch {}
  }
  return files;
}

const ANALYSIS_TYPE_MAP: Record<string, "explain" | "security" | "logic" | "full"> = {
  quick: "explain",
  functionality: "logic",
  explain: "explain",
  security: "security",
  logic: "logic",
  full: "full",
};

router.post("/decompile", upload.single("file"), async (req: Request, res: Response) => {
  extendTimeout(req, res);
  const file = req.file;
  if (!file) { res.status(400).json({ error: "لم يتم رفع ملف" }); return; }
  try {
    const buf = readUploadedFile(file);
    const result = await decompileByType(buf, file.originalname);
    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message, success: false });
  }
});

router.post("/analyze", async (req: Request, res: Response) => {
  extendTimeout(req, res);
  const { code, fileContent, fileName, analysisType = "full", question, files, manifest } = req.body as {
    code?: string; fileContent?: string; fileName: string;
    analysisType?: "full" | "security" | "quick" | "functionality";
    question?: string; files?: any[]; manifest?: any;
  };
  const content = code || fileContent || "";
  try {
    let analysis: string;
    if (content || files) {
      const mappedType = ANALYSIS_TYPE_MAP[analysisType] || "full";
      analysis = await analyzeWithAI(content, fileName, mappedType, question, files, manifest);
    } else {
      const r = await callPowerAI(
        "أنت خبير في الهندسة العكسية وتحليل البرمجيات.",
        `حلل هذا الملف: ${fileName}\nنوع التحليل: ${analysisType}${question ? `\nالسؤال: ${question}` : ""}`,
        8192
      );
      analysis = r.content;
    }
    res.json({ analysis, fileName, analysisType });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/decompile-for-edit", upload.single("file"), async (req: Request, res: Response) => {
  extendTimeout(req, res);
  const file = req.file;
  if (!file) { res.status(400).json({ error: "لم يتم رفع ملف" }); return; }
  try {
    const buf = readUploadedFile(file);
    const result = await decompileFileForEdit(buf, file.originalname);
    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message, success: false });
  }
});

router.get("/session/:sessionId", (req: Request, res: Response) => {
  try {
    const info = getSessionInfo(req.params.sessionId);
    res.json(info);
  } catch (e: any) {
    res.status(404).json({ error: "Session not found", details: e.message });
  }
});

router.post("/file-content", (req: Request, res: Response) => {
  const { sessionId, filePath } = req.body as { sessionId: string; filePath: string };
  if (!sessionId || !filePath) { res.status(400).json({ error: "sessionId and filePath required" }); return; }
  const result = readSessionFileContent(sessionId, filePath);
  if (!result.success) { res.status(404).json(result); return; }
  res.json(result);
});

router.get("/file-content", (req: Request, res: Response) => {
  const { sessionId, filePath } = req.query as { sessionId: string; filePath: string };
  if (!sessionId || !filePath) { res.status(400).json({ error: "sessionId and filePath required" }); return; }
  const result = readSessionFileContent(sessionId, filePath);
  if (!result.success) { res.status(404).json(result); return; }
  res.json(result);
});

router.post("/save-edit", (req: Request, res: Response) => {
  const { sessionId, filePath, content } = req.body as { sessionId: string; filePath: string; content: string };
  if (!sessionId || !filePath || content === undefined) { res.status(400).json({ error: "sessionId, filePath, and content required" }); return; }
  try {
    const result = saveFileEdit(sessionId, filePath, content);
    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/ai-modify", async (req: Request, res: Response) => {
  const { code, instruction, fileName } = req.body as {
    code?: string; instruction?: string; fileName?: string;
  };
  if (!instruction) { res.status(400).json({ error: "instruction required" }); return; }
  try {
    if (!code || !fileName) { res.status(400).json({ error: "code and fileName required" }); return; }
    const result = await aiModifyCode(code, instruction, fileName);
    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/ai-search", async (req: Request, res: Response) => {
  const { sessionId, query } = req.body as { sessionId: string; query: string };
  if (!sessionId || !query) { res.status(400).json({ error: "sessionId and query required" }); return; }
  try {
    const result = await aiSearchFiles(sessionId, query);
    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/ai-smart-modify", async (req: Request, res: Response) => {
  const { sessionId, instruction, targetFiles } = req.body as {
    sessionId: string; instruction: string; targetFiles?: string[];
  };
  if (!sessionId || !instruction) { res.status(400).json({ error: "sessionId and instruction required" }); return; }
  try {
    const result = await aiSmartModify(sessionId, instruction, targetFiles);
    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/rebuild", async (req: Request, res: Response) => {
  extendTimeout(req, res);
  const { sessionId } = req.body as { sessionId: string };
  if (!sessionId) { res.status(400).json({ error: "sessionId required" }); return; }
  try {
    const result = await rebuildAPK(sessionId);
    if (result.success && result.apkBuffer) {
      res.setHeader("Content-Type", "application/vnd.android.package-archive");
      res.setHeader("Content-Disposition", `attachment; filename="rebuilt_${sessionId}.apk"`);
      if ((result as any).signed) res.setHeader("X-APK-Signed", "true");
      res.send(result.apkBuffer);
    } else {
      res.status(500).json({ error: result.error || "فشل إعادة البناء" });
    }
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/clone", upload.single("file"), async (req: Request, res: Response) => {
  extendTimeout(req, res);
  const file = req.file;
  if (!file) { res.status(400).json({ error: "لم يتم رفع ملف" }); return; }
  const body = req.body as Record<string, string>;
  const options = {
    removeAds:          body.removeAds !== "false",
    unlockPremium:      body.unlockPremium !== "false",
    removeTracking:     body.removeTracking === "true",
    removeLicenseCheck: body.removeLicenseCheck !== "false",
    changeAppName:      body.changeAppName || undefined,
    changePackageName:  body.changePackageName || undefined,
    customInstructions: body.customInstructions || undefined,
  };
  try {
    const buf = readUploadedFile(file);
    const result = await cloneApp(buf, file.originalname, options);
    if (!result.success || !result.apkBuffer) {
      res.setHeader("X-Modifications", encodeURIComponent(JSON.stringify(result.modifications || [])));
      res.status(500).json({ error: result.error || "فشل الاستنساخ", modifications: result.modifications });
      return;
    }
    const ext = file.originalname.split(".").pop()?.toLowerCase();
    const outExt = ext === "apk" ? "apk" : "zip";
    res.setHeader("Content-Type", ext === "apk" ? "application/vnd.android.package-archive" : "application/zip");
    const baseName = file.originalname.replace(/\.[^.]+$/, "");
    res.setHeader("Content-Disposition", `attachment; filename="cloned-${baseName}.${outExt}"`);
    res.setHeader("X-Modifications", encodeURIComponent(JSON.stringify(result.modifications || [])));
    res.setHeader("X-Patched-Files", String(result.modifications?.filter((m: string) => m.includes("ملف") || m.includes("smali") || m.includes("xml")).length || result.modifications?.length || 0));
    if (result.signed) res.setHeader("X-APK-Signed", "true");
    res.send(result.apkBuffer);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/intelligence-report", async (req: Request, res: Response) => {
  const { sessionId } = req.body as { sessionId: string };
  if (!sessionId) { res.status(400).json({ error: "sessionId required" }); return; }
  try {
    const result = await generateIntelligenceReport(sessionId);
    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/regex-search", (req: Request, res: Response) => {
  const { sessionId, pattern, category } = req.body as { sessionId: string; pattern?: string; category?: string };
  if (!sessionId) { res.status(400).json({ error: "sessionId required" }); return; }
  try {
    const results = regexSearchFiles(sessionId, pattern || ".", category);
    res.json({ results, pattern, category, sessionId });
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});

router.post("/revert-file", (req: Request, res: Response) => {
  const { sessionId, filePath } = req.body as { sessionId: string; filePath: string };
  if (!sessionId || !filePath) { res.status(400).json({ error: "sessionId and filePath required" }); return; }
  try {
    const result = revertFile(sessionId, filePath);
    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post("/certificate", upload.single("file"), async (req: Request, res: Response) => {
  try {
    if (!req.file) { res.status(400).json({ error: "ارفع ملف APK" }); return; }
    const result = await analyzeCertificate(readUploadedFile(req.file));
    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/permission-risk", async (req: Request, res: Response) => {
  try {
    const { permissions } = req.body;
    if (!permissions?.length) { res.status(400).json({ error: "أرسل قائمة الأذونات" }); return; }
    res.json(analyzePermissionRisk(permissions));
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/network-endpoints", async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) { res.status(400).json({ error: "sessionId مطلوب" }); return; }
    const files = getSessionFiles(sessionId);
    if (!files) { res.status(404).json({ error: "الجلسة غير موجودة" }); return; }
    res.json(extractNetworkEndpoints(files));
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/detect-obfuscation", async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) { res.status(400).json({ error: "sessionId مطلوب" }); return; }
    const files = getSessionFiles(sessionId);
    if (!files) { res.status(404).json({ error: "الجلسة غير موجودة" }); return; }
    res.json(detectObfuscation(files));
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/malware-scan", async (req: Request, res: Response) => {
  try {
    const { sessionId, permissions } = req.body;
    if (!sessionId) { res.status(400).json({ error: "sessionId مطلوب" }); return; }
    const files = getSessionFiles(sessionId);
    if (!files) { res.status(404).json({ error: "الجلسة غير موجودة" }); return; }
    res.json(detectMalwarePatterns(files, permissions || []));
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/ai-vuln-scan", async (req: Request, res: Response) => {
  try {
    const { code, fileName, fileType } = req.body;
    if (!code) { res.status(400).json({ error: "أرسل الكود" }); return; }
    res.json(await aiVulnerabilityScan(code, fileName || "unknown", fileType || "unknown"));
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/ai-decompile-smali", async (req: Request, res: Response) => {
  try {
    const { smaliCode, className } = req.body;
    if (!smaliCode) { res.status(400).json({ error: "أرسل كود Smali" }); return; }
    const java = await aiDecompileSmali(smaliCode, className || "Unknown");
    res.json({ javaCode: java });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/extract-strings", upload.single("file"), async (req: Request, res: Response) => {
  try {
    if (!req.file) { res.status(400).json({ error: "ارفع ملف" }); return; }
    res.json(extractStringsFromBinary(readUploadedFile(req.file), parseInt(req.body.minLength) || 4));
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/parse-dex", upload.single("file"), async (req: Request, res: Response) => {
  try {
    if (!req.file) { res.status(400).json({ error: "ارفع ملف DEX" }); return; }
    const header = parseDEXHeader(readUploadedFile(req.file));
    if (!header) { res.status(400).json({ error: "ملف DEX غير صالح" }); return; }
    res.json(header);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/parse-pe", upload.single("file"), async (req: Request, res: Response) => {
  try {
    if (!req.file) { res.status(400).json({ error: "ارفع ملف EXE/DLL" }); return; }
    const header = parsePEHeaderDetailed(readUploadedFile(req.file));
    if (!header) { res.status(400).json({ error: "ملف PE غير صالح" }); return; }
    res.json(header);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.get("/download/:downloadId", (req: Request, res: Response) => {
  const { downloadId } = req.params;
  const sessions = (global as any).__reverseDownloads || new Map();
  const filePath = sessions.get(downloadId);
  if (!filePath) { res.status(404).json({ error: "رابط التحميل غير صالح أو منتهي" }); return; }
  if (!fs.existsSync(filePath)) { res.status(404).json({ error: "الملف غير موجود" }); return; }
  res.download(filePath, path.basename(filePath));
});

router.get("/tools-status", async (_req: Request, res: Response) => {
  try {
    const java = isJavaAvailable();
    const apktool = isApkToolAvailable();
    const apktoolPath = findApkTool();

    let jadx = false;
    try { const { execSync } = require("child_process"); execSync("/home/runner/jadx/bin/jadx --version", { timeout: 5000, stdio: "pipe" }); jadx = true; } catch {
      try { const { execSync } = require("child_process"); execSync("jadx --version", { timeout: 5000, stdio: "pipe" }); jadx = true; } catch {}
    }

    let zipalign = false;
    try { const { execSync } = require("child_process"); execSync("zipalign --version 2>&1", { timeout: 5000, stdio: "pipe" }); zipalign = true; } catch {
      try { const fs = require("fs"); if (fs.existsSync("/home/runner/zipalign") || fs.existsSync("/usr/bin/zipalign")) zipalign = true; } catch {}
    }

    res.json({
      tools: {
        java: { installed: java, required: true, purpose: "تشغيل APKTool و JADX" },
        apktool: { installed: apktool, required: true, path: apktoolPath, purpose: "تفكيك Smali وإعادة البناء" },
        jadx: { installed: jadx, required: false, purpose: "تحويل DEX → Java (اختياري — AI يعوّضه)" },
        zipalign: { installed: zipalign, required: false, purpose: "محاذاة APK (تحسين)" },
      },
      capabilities: {
        decompile: { available: true, note: "تفكيك ZIP دائماً متاح" },
        decompileSmali: { available: apktool, note: apktool ? "APKTool متاح" : "يحتاج APKTool" },
        decompileJava: { available: jadx || true, note: jadx ? "JADX متاح" : "AI يحوّل Smali→Java بدلاً من JADX" },
        edit: { available: true, note: "تعديل الملفات متاح دائماً" },
        rebuild: { available: (apktool && java) || true, note: (apktool && java) ? "APKTool rebuild متاح" : "ZIP rebuild متاح" },
        sign: { available: java, note: java ? "توقيع APK متاح" : "يحتاج Java لتوقيع APK" },
        aiAnalysis: { available: true, note: "تحليل AI متاح دائماً" },
      },
      recommendation: !java
        ? "⚠️ Java غير مثبت"
        : !apktool
        ? "🔄 APKTool سيتم تثبيته تلقائياً عند أول عملية تفكيك"
        : "✅ كل الأدوات جاهزة",
    });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/hex-dump", async (req: Request, res: Response) => {
  const { sessionId, filePath, offset: reqOffset, length: reqLength } = req.body as { sessionId: string; filePath: string; offset?: number; length?: number };
  if (!sessionId || !filePath) { res.status(400).json({ error: "sessionId and filePath required" }); return; }
  try {
    const session = editSessions.get(sessionId);
    if (!session) { res.status(404).json({ error: "الجلسة غير موجودة" }); return; }
    const fullPath = path.join(session.decompDir, filePath);
    if (!fs.existsSync(fullPath)) { res.status(404).json({ error: "الملف غير موجود" }); return; }
    const stat = fs.statSync(fullPath);
    const readOffset = reqOffset || 0;
    const readLength = Math.min(reqLength || 512, 4096);
    const fd = fs.openSync(fullPath, "r");
    const buf = Buffer.alloc(readLength);
    const bytesRead = fs.readSync(fd, buf, 0, readLength, readOffset);
    fs.closeSync(fd);
    const bytes = Array.from(buf.slice(0, bytesRead));
    const rows = [];
    for (let i = 0; i < bytesRead; i += 16) {
      const rowBytes = bytes.slice(i, Math.min(i + 16, bytesRead));
      const offset = (readOffset + i).toString(16).padStart(8, "0").toUpperCase();
      const hex = rowBytes.map(b => b.toString(16).padStart(2, "0").toUpperCase());
      const ascii = rowBytes.map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : "·").join("");
      rows.push({ offset, bytes: hex, ascii });
    }
    res.json({ rows, totalSize: stat.size, readOffset, bytesRead });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════
// Advanced Forensics Endpoints
// ════════════════════════════════════════

router.post("/decode-strings", async (req: Request, res: Response) => {
  const { sessionId } = req.body as { sessionId: string };
  if (!sessionId) { res.status(400).json({ error: "sessionId required" }); return; }
  try {
    const session = editSessions.get(sessionId);
    if (!session) { res.status(404).json({ error: "الجلسة غير موجودة" }); return; }
    const allFiles = readDirRecursive(session.decompDir);
    const textExts = [".smali", ".java", ".kt", ".xml", ".json", ".properties", ".txt", ".yml", ".yaml", ".js"];
    const files: any[] = [];
    for (const fp of allFiles.slice(0, 5000)) {
      const ext = path.extname(fp).toLowerCase();
      if (!textExts.includes(ext)) continue;
      try {
        const stat = fs.statSync(fp);
        if (stat.size > 500_000) continue;
        files.push({ path: path.relative(session.decompDir, fp), name: path.basename(fp), extension: ext, size: stat.size, content: fs.readFileSync(fp, "utf-8"), isBinary: false });
      } catch { /* skip */ }
    }
    const result = decodeStringsInFiles(files);
    res.json({ decoded: result, total: result.length });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/cross-reference", async (req: Request, res: Response) => {
  const { sessionId, target } = req.body as { sessionId: string; target: string };
  if (!sessionId || !target) { res.status(400).json({ error: "sessionId and target required" }); return; }
  try {
    const result = crossReference(sessionId, target);
    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/class-hierarchy", async (req: Request, res: Response) => {
  const { sessionId } = req.body as { sessionId: string };
  if (!sessionId) { res.status(400).json({ error: "sessionId required" }); return; }
  try {
    const result = buildClassHierarchy(sessionId);
    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/diff", upload.fields([{ name: "file1", maxCount: 1 }, { name: "file2", maxCount: 1 }]), async (req: Request, res: Response) => {
  extendTimeout(req, res);
  const files = req.files as { [fieldname: string]: Express.Multer.File[] };
  if (!files?.file1?.[0] || !files?.file2?.[0]) { res.status(400).json({ error: "يجب رفع ملفين" }); return; }
  try {
    const result = await diffAPKs(files.file1[0].buffer, files.file2[0].buffer, files.file1[0].originalname, files.file2[0].originalname);
    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/data-flow", async (req: Request, res: Response) => {
  const { sessionId } = req.body as { sessionId: string };
  if (!sessionId) { res.status(400).json({ error: "sessionId required" }); return; }
  try {
    const result = analyzeDataFlow(sessionId);
    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/method-search", async (req: Request, res: Response) => {
  const { sessionId, query } = req.body as { sessionId: string; query: string };
  if (!sessionId || !query) { res.status(400).json({ error: "sessionId and query required" }); return; }
  try {
    const result = methodSignatureSearch(sessionId, query);
    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/forensic-report", async (req: Request, res: Response) => {
  extendTimeout(req, res);
  const { sessionId, analyses } = req.body as { sessionId: string; analyses: any };
  if (!sessionId) { res.status(400).json({ error: "sessionId required" }); return; }
  try {
    const result = await generateForensicReport(sessionId, analyses || { decodedStrings: true, classHierarchy: true, dataFlow: true, networkEndpoints: true, obfuscation: true, malware: true });
    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.get("/check-tools", async (_req: Request, res: Response) => {
  try {
    res.json(getToolStatus());
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

router.post("/cloud-pentest", async (req: Request, res: Response) => {
  extendTimeout(req, res, 600_000);
  const { sessionId } = req.body as { sessionId: string };
  if (!sessionId) { res.status(400).json({ error: "sessionId مطلوب" }); return; }
  try {
    const { runCloudPentest } = await import("../hayo/services/reverse-engineer.js");
    const result = await runCloudPentest(sessionId);
    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});


router.post("/cloud-pentest-full", upload.single("file"), async (req: Request, res: Response) => {
  extendTimeout(req, res, 600_000);
  if (!req.file) { res.status(400).json({ error: "ارفع ملف APK أولاً" }); return; }
  try {
    const { decompileFileForEdit, runCloudPentest } = await import("../hayo/services/reverse-engineer.js");
    const editResult = await decompileFileForEdit(readUploadedFile(req.file), req.file.originalname);
    const pentestResult = await runCloudPentest(editResult.sessionId);
    const result = {
      ...pentestResult,
      sessionId: editResult.sessionId,
      fileName: req.file.originalname,
      fileSize: req.file.size,
    };

    try {
      await sendPentestToTelegram(result);
      console.log("[Pentest-TG] ✅ All messages sent to Telegram");
    } catch (tgErr: any) {
      console.log("[Pentest-TG] ❌ Error:", tgErr.message);
    }

    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

async function sendPentestToTelegram(result: any) {
  const botToken = process.env.PENTEST_BOT_TOKEN;
  const chatId = process.env.PENTEST_CHAT_ID;
  console.log(`[Pentest-TG] token=${botToken ? "YES" : "NO"}, chatId=${chatId || "MISSING"}`);
  if (!botToken || !chatId) { console.log("[Pentest-TG] SKIP — missing env vars"); return; }

  const send = async (text: string, parseMode = "HTML") => {
    const chunks: string[] = [];
    for (let i = 0; i < text.length; i += 4000) chunks.push(text.substring(i, i + 4000));
    for (const chunk of chunks) {
      const r = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: chatId, text: chunk, parse_mode: parseMode }),
      });
      const j = await r.json() as any;
      if (!j.ok) console.log("[Pentest-TG] ERR:", j.description);
    }
  };

  const s = result.summary;
  const riskEmoji = s.riskScore > 60 ? "🔴" : s.riskScore > 30 ? "🟡" : "🟢";

  let header = `🔓 <b>HAYO AI — تقرير اختبار اختراق سحابي</b>\n`;
  header += `━━━━━━━━━━━━━━━━━━━━━━\n`;
  header += `📁 <b>الملف:</b> <code>${result.fileName || "APK"}</code>\n`;
  header += `📊 <b>الحجم:</b> ${result.fileSize ? ((result.fileSize / 1024 / 1024).toFixed(1) + " MB") : "N/A"}\n`;
  header += `${riskEmoji} <b>درجة الخطورة:</b> ${s.riskScore}/100\n`;
  header += `🔴 <b>حرج:</b> ${s.criticalCount} | 🟡 <b>تحذيرات:</b> ${s.highCount}\n`;
  header += `🔑 <b>مفاتيح:</b> ${s.extractedKeys?.length || 0} | 🌐 <b>نقاط دخول:</b> ${s.extractedEndpoints?.length || 0}\n`;
  header += `☁️ <b>تقنيات:</b> ${s.cloudProviders?.join(", ") || "لا يوجد"}\n`;
  header += `⏰ <b>التوقيت:</b> ${new Date(result.generatedAt).toLocaleString("ar-EG")}\n`;
  header += `━━━━━━━━━━━━━━━━━━━━━━`;
  await send(header);

  for (const step of result.steps) {
    const statusIcons: Record<string, string> = { critical: "🔴", warning: "🟡", info: "🔵", success: "🟢" };
    let msg = `${statusIcons[step.status] || "⚪"} <b>الخطوة ${step.id}: ${step.title}</b>\n`;
    msg += `📋 ${step.details}\n`;
    if (step.findings?.length > 0) {
      msg += `\n<b>الاكتشافات (${step.findings.length}):</b>\n`;
      const maxFindings = (step.id === 4 || step.id === 6) ? 50 : 15;
      for (const f of step.findings.slice(0, maxFindings)) msg += `${f}\n`;
      if (step.findings.length > maxFindings) msg += `... +${step.findings.length - maxFindings} نتائج أخرى\n`;
    }
    if (step.commands?.length > 0) {
      msg += `\n<b>الأوامر (${step.commands.length}):</b>\n`;
      for (const c of step.commands.slice(0, 8)) msg += `<code>${c}</code>\n`;
      if (step.commands.length > 8) msg += `... +${step.commands.length - 8} أوامر أخرى\n`;
    }
    await send(msg);
  }

  if (s.extractedKeys?.length > 0) {
    let keysMsg = `🔑 <b>المفاتيح المستخرجة:</b>\n`;
    for (const k of s.extractedKeys.slice(0, 10)) keysMsg += `<code>${k}</code>\n`;
    await send(keysMsg);
  }

  if (s.extractedEndpoints?.length > 0) {
    let urlMsg = `🌐 <b>نقاط الدخول المكتشفة:</b>\n`;
    for (const u of s.extractedEndpoints.slice(0, 15)) urlMsg += `<code>${u}</code>\n`;
    await send(urlMsg);
  }

  if (result.report) {
    await send(`📄 <b>التقرير الاحترافي (AI):</b>\n\n${result.report}`, "HTML");
  }

  await send(`✅ <b>انتهى اختبار الاختراق السحابي — HAYO AI RE:PLATFORM</b>`);

  try {
    const jsonBuffer = Buffer.from(JSON.stringify(result, null, 2));
    const form = new FormData();
    form.append("chat_id", chatId);
    form.append("document", new Blob([jsonBuffer], { type: "application/json" }), `pentest-${Date.now()}.json`);
    form.append("caption", `📊 تقرير اختبار الاختراق — ${result.fileName} — الخطورة: ${s.riskScore}/100`);
    await fetch(`https://api.telegram.org/bot${botToken}/sendDocument`, { method: "POST", body: form });
  } catch {}
}

const uploadStore = new Map<string, { filePath: string; fileName: string; uploadedAt: number }>();
setInterval(() => {
  const now = Date.now();
  for (const [id, u] of uploadStore) {
    if (now - u.uploadedAt > 30 * 60 * 1000) { try { fs.unlinkSync(u.filePath); } catch {} uploadStore.delete(id); }
  }
}, 60_000);

router.post("/upload", upload.single("file"), (req: Request, res: Response) => {
  if (!req.file) { res.status(400).json({ error: "لم يتم رفع ملف" }); return; }
  const uploadId = `up_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  uploadStore.set(uploadId, { filePath: req.file.path, fileName: req.file.originalname, uploadedAt: Date.now() });
  res.json({ uploadId, fileName: req.file.originalname, size: req.file.size });
});

function sseHeaders(res: Response) {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();
}
function sseSend(res: Response, msg: string) { res.write(`data: ${msg}\n\n`); }
function sseJSON(res: Response, event: string, data: any) { res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); }

function spawnStream(res: Response, cmd: string, args: string[], cwd: string, label: string): Promise<number> {
  return new Promise((resolve) => {
    sseSend(res, `[STEP] ${label}`);
    sseSend(res, `$ ${cmd} ${args.join(" ")}`);
    const child = spawn(cmd, args, { cwd, timeout: 300_000 });
    child.stdout.on("data", (d: Buffer) => { for (const l of d.toString().split("\n").filter(Boolean)) sseSend(res, l); });
    child.stderr.on("data", (d: Buffer) => { for (const l of d.toString().split("\n").filter(Boolean)) sseSend(res, `[WARN] ${l}`); });
    child.on("error", (e) => { sseSend(res, `[ERROR] ${e.message}`); resolve(1); });
    child.on("close", (code) => { sseSend(res, `[EXIT] ${cmd} → ${code}`); resolve(code ?? 1); });
    (res as any)._sseChild = child;
  });
}

router.get("/stream/decompile", async (req: Request, res: Response) => {
  sseHeaders(res);
  const uploadId = req.query.uploadId as string;
  const upload = uploadStore.get(uploadId);
  if (!upload) { sseSend(res, "[ERROR] ملف غير موجود — ارفع أولاً"); res.end(); return; }

  const { filePath, fileName } = upload;
  const ext = fileName.split(".").pop()?.toLowerCase() || "";
  const workDir = path.join(os.tmpdir(), `hayo_decomp_${Date.now()}`);
  fs.mkdirSync(workDir, { recursive: true });

  req.on("close", () => { try { (res as any)._sseChild?.kill(); } catch {} });

  try {
    if (ext === "apk") {
      const apktoolOut = path.join(workDir, "apktool_out");
      const jadxOut = path.join(workDir, "jadx_out");

      sseSend(res, `[INFO] بدء تفكيك ${fileName} (${(fs.statSync(filePath).size / 1048576).toFixed(1)} MB)`);

      const code1 = await spawnStream(res, "apktool", ["d", "-f", "-o", apktoolOut, filePath], workDir, "apktool — تفكيك Smali + الموارد");
      if (code1 !== 0) sseSend(res, "[WARN] apktool أنهى بخطأ — سنستمر بـ jadx");

      const code2 = await spawnStream(res, "jadx", ["-d", jadxOut, "--no-res", filePath], workDir, "jadx — تحويل إلى Java");
      if (code2 !== 0) sseSend(res, "[WARN] jadx أنهى بخطأ — سنستمر بالملفات المتوفرة");

      let totalFiles = 0;
      const countDir = (d: string) => { try { for (const e of fs.readdirSync(d, { withFileTypes: true })) { if (e.isFile()) totalFiles++; else if (e.isDirectory()) countDir(path.join(d, e.name)); } } catch {} };
      countDir(apktoolOut); countDir(jadxOut);

      sseSend(res, `[INFO] إجمالي الملفات: ${totalFiles}`);

      const buf = fs.readFileSync(filePath);
      const result = await decompileByType(buf, fileName);

      sseJSON(res, "result", result);
      sseSend(res, `[DONE] تفكيك ${fileName} اكتمل — ${result.totalFiles} ملف`);

    } else if (ext === "exe" || ext === "dll") {
      sseSend(res, `[INFO] تحليل ${ext.toUpperCase()}: ${fileName}`);
      await spawnStream(res, "file", [filePath], workDir, "تحديد نوع الملف");
      await spawnStream(res, "strings", ["-n", "8", filePath], workDir, "استخراج النصوص");

      const buf = fs.readFileSync(filePath);
      const result = await decompileByType(buf, fileName);
      sseJSON(res, "result", result);
      sseSend(res, `[DONE] تحليل ${fileName} اكتمل`);

    } else if (ext === "jar" || ext === "aar") {
      sseSend(res, `[INFO] تفكيك ${ext.toUpperCase()}: ${fileName}`);
      const jadxOut = path.join(workDir, "jadx_out");
      await spawnStream(res, "jadx", ["-d", jadxOut, filePath], workDir, "jadx — تحويل JAR إلى Java");

      const buf = fs.readFileSync(filePath);
      const result = await decompileByType(buf, fileName);
      sseJSON(res, "result", result);
      sseSend(res, `[DONE] تفكيك ${fileName} اكتمل — ${result.totalFiles} ملف`);

    } else if (ext === "dex") {
      sseSend(res, `[INFO] تفكيك DEX: ${fileName}`);
      const jadxOut = path.join(workDir, "jadx_out");
      await spawnStream(res, "jadx", ["-d", jadxOut, filePath], workDir, "jadx — تحويل DEX إلى Java");

      const buf = fs.readFileSync(filePath);
      const result = await decompileByType(buf, fileName);
      sseJSON(res, "result", result);
      sseSend(res, `[DONE] تفكيك ${fileName} اكتمل`);

    } else if (ext === "so" || ext === "elf") {
      sseSend(res, `[INFO] تحليل ELF/SO: ${fileName}`);
      await spawnStream(res, "file", [filePath], workDir, "تحديد نوع الملف");
      await spawnStream(res, "readelf", ["-h", filePath], workDir, "قراءة ELF Header");
      await spawnStream(res, "readelf", ["-S", filePath], workDir, "قراءة الأقسام");
      await spawnStream(res, "objdump", ["-x", filePath], workDir, "تصدير الرموز");

      const buf = fs.readFileSync(filePath);
      const result = await decompileByType(buf, fileName);
      sseJSON(res, "result", result);
      sseSend(res, `[DONE] تحليل ${fileName} اكتمل`);

    } else if (ext === "wasm") {
      sseSend(res, `[INFO] تحليل WebAssembly: ${fileName}`);
      const watOut = path.join(workDir, "output.wat");
      await spawnStream(res, "wasm2wat", [filePath, "-o", watOut], workDir, "wasm2wat — تحويل إلى WAT");

      const buf = fs.readFileSync(filePath);
      const result = await decompileByType(buf, fileName);
      sseJSON(res, "result", result);
      sseSend(res, `[DONE] تحليل ${fileName} اكتمل`);

    } else {
      sseSend(res, `[INFO] تحليل ${ext.toUpperCase()}: ${fileName}`);
      const buf = fs.readFileSync(filePath);
      const result = await decompileByType(buf, fileName);
      sseJSON(res, "result", result);
      sseSend(res, `[DONE] تحليل ${fileName} اكتمل`);
    }
  } catch (e: any) {
    sseSend(res, `[ERROR] ${e.message}`);
  }
  res.end();
});

router.get("/stream/clone", async (req: Request, res: Response) => {
  sseHeaders(res);
  const uploadId = req.query.uploadId as string;
  const upload = uploadStore.get(uploadId);
  if (!upload) { sseSend(res, "[ERROR] ملف غير موجود"); res.end(); return; }

  const { filePath, fileName } = upload;
  const ext = fileName.split(".").pop()?.toLowerCase() || "";
  const workDir = path.join(os.tmpdir(), `hayo_clone_${Date.now()}`);
  fs.mkdirSync(workDir, { recursive: true });

  let opts: any = {};
  try { opts = JSON.parse(req.query.opts as string || "{}"); } catch {}

  req.on("close", () => { try { (res as any)._sseChild?.kill(); } catch {} });

  try {
    if (ext === "apk") {
      const decodeDir = path.join(workDir, "decoded");

      sseSend(res, `[STEP] الخطوة 1/4: تفكيك APK`);
      const code1 = await spawnStream(res, "apktool", ["d", "-f", "-o", decodeDir, filePath], workDir, "apktool d — تفكيك الحزمة");
      if (code1 !== 0) { sseSend(res, "[ERROR] فشل التفكيك"); sseJSON(res, "result", { success: false, error: "فشل apktool d" }); res.end(); return; }

      sseSend(res, `[STEP] الخطوة 2/4: تعديل الملفات`);
      const buf = fs.readFileSync(filePath);
      const result = await cloneApp(buf, fileName, {
        removeAds: opts.removeAds !== false,
        unlockPremium: opts.unlockPremium !== false,
        removeTracking: opts.removeTracking === true,
        removeLicenseCheck: opts.removeLicenseCheck !== false,
        changeAppName: opts.changeAppName || undefined,
        changePackageName: opts.changePackageName || undefined,
        customInstructions: opts.customInstructions || undefined,
      });

      for (const m of result.modifications) sseSend(res, `[MOD] ${m}`);

      if (result.success && result.apkBuffer) {
        const outPath = path.join(workDir, `cloned-${fileName}`);
        fs.writeFileSync(outPath, result.apkBuffer);
        sseSend(res, `[STEP] الخطوة 4/4: الملف جاهز (${(result.apkBuffer.length / 1048576).toFixed(1)} MB)`);
        if (result.signed) sseSend(res, "[INFO] تم التوقيع بنجاح");

        const dlId = `dl_${Date.now()}`;
        uploadStore.set(dlId, { filePath: outPath, fileName: `cloned-${fileName}`, uploadedAt: Date.now() });
        sseJSON(res, "result", { success: true, modifications: result.modifications, signed: result.signed, patchedFiles: result.modifications.length, downloadId: dlId });
      } else {
        sseJSON(res, "result", { success: false, error: result.error, modifications: result.modifications });
      }
      sseSend(res, `[DONE] استنساخ ${fileName} اكتمل`);

    } else {
      sseSend(res, `[INFO] استنساخ ${ext.toUpperCase()}: ${fileName}`);
      const buf = fs.readFileSync(filePath);
      const result = await cloneApp(buf, fileName, {
        removeAds: opts.removeAds !== false,
        unlockPremium: opts.unlockPremium !== false,
        removeTracking: opts.removeTracking === true,
        removeLicenseCheck: opts.removeLicenseCheck !== false,
        changeAppName: opts.changeAppName,
        changePackageName: opts.changePackageName,
        customInstructions: opts.customInstructions,
      });
      for (const m of result.modifications) sseSend(res, `[MOD] ${m}`);
      if (result.success && result.apkBuffer) {
        const outPath = path.join(workDir, `cloned-${fileName}.zip`);
        fs.writeFileSync(outPath, result.apkBuffer);
        const dlId = `dl_${Date.now()}`;
        uploadStore.set(dlId, { filePath: outPath, fileName: `cloned-${fileName}.zip`, uploadedAt: Date.now() });
        sseJSON(res, "result", { success: true, modifications: result.modifications, signed: result.signed || false, patchedFiles: result.modifications.length, downloadId: dlId });
      } else {
        sseJSON(res, "result", { success: false, error: result.error, modifications: result.modifications });
      }
      sseSend(res, `[DONE] استنساخ ${fileName} اكتمل`);
    }
  } catch (e: any) {
    sseSend(res, `[ERROR] ${e.message}`);
    sseJSON(res, "result", { success: false, error: e.message, modifications: [] });
  }
  res.end();
});

router.get("/stream/download/:dlId", (req: Request, res: Response) => {
  const dl = uploadStore.get(req.params.dlId);
  if (!dl || !fs.existsSync(dl.filePath)) { res.status(404).json({ error: "ملف غير موجود" }); return; }
  res.download(dl.filePath, dl.fileName);
});

const ALLOWED_CMDS = new Set(["apktool", "jadx", "jarsigner", "aapt", "aapt2", "adb", "zipalign", "7zz", "xxd", "objdump", "readelf", "wasm2wat", "file", "strings"]);

router.get("/stream/execute", (req: Request, res: Response) => {
  sseHeaders(res);
  const cmd = req.query.cmd as string;
  if (!cmd || !ALLOWED_CMDS.has(cmd)) { sseSend(res, `[ERROR] الأمر غير مسموح: ${cmd}`); res.end(); return; }
  let args: string[] = [];
  try { args = JSON.parse((req.query.args as string) || "[]"); } catch { args = []; }
  const cwd = (req.query.cwd as string) || os.tmpdir();
  const child = spawn(cmd, args, { cwd, timeout: 300_000 });
  child.stdout.on("data", (d: Buffer) => { for (const l of d.toString().split("\n").filter(Boolean)) sseSend(res, l); });
  child.stderr.on("data", (d: Buffer) => { for (const l of d.toString().split("\n").filter(Boolean)) sseSend(res, `[WARN] ${l}`); });
  child.on("close", (code) => { sseSend(res, `[DONE] Exit Code: ${code}`); res.end(); });
  child.on("error", (err) => { sseSend(res, `[ERROR] ${err.message}`); res.end(); });
  req.on("close", () => { try { child.kill(); } catch {} });
});

export default router;
