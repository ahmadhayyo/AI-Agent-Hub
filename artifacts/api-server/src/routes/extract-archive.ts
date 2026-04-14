/**
 * Extract Archive Routes
 * POST /api/files/extract-archive
 * Accepts both multipart FormData (field: "file") and JSON base64 body.
 */
import { Router, type Request, type Response } from "express";
import multer from "multer";
import JSZip from "jszip";

const router = Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 },
});

const textExtensions = new Set([
  "txt", "xml", "json", "properties", "cfg", "ini",
  "html", "css", "js", "ts", "kt", "java", "smali",
  "gradle", "pro", "md", "yml", "yaml", "mf", "sf",
  "manifest", "plist", "py", "rb", "php", "c", "cpp",
  "h", "swift", "dart", "go", "rs",
]);

async function extractZip(buffer: Buffer, fileName: string, res: Response) {
  const ext = fileName.split(".").pop()?.toLowerCase() || "";
  if (!["zip", "jar", "apk", "ipa"].includes(ext)) {
    res.status(400).json({
      error: `صيغة الملف .${ext} غير مدعومة. الصيغ المدعومة: zip, jar, apk, ipa`,
    });
    return;
  }

  const zip = await JSZip.loadAsync(buffer);

  const files: {
    name: string;
    path: string;
    size: number;
    compressedSize: number;
    isDirectory: boolean;
    content?: string;
  }[] = [];

  const entries = Object.entries(zip.files);
  for (const [path, file] of entries) {
    const isDirectory = file.dir;
    const fileExt = path.split(".").pop()?.toLowerCase() || "";
    const isText = textExtensions.has(fileExt);

    let content: string | undefined;
    let size = 0;

    try {
      const arrayBuffer = await file.async("arraybuffer");
      size = arrayBuffer.byteLength;

      if (!isDirectory && isText && size < 200_000) {
        content = await file.async("string");
        if (content.includes("\0")) content = undefined;
      }
    } catch {
      size = 0;
    }

    files.push({
      name: path.split("/").pop() || path,
      path,
      size,
      compressedSize: (file as any)._data?.compressedSize || 0,
      isDirectory,
      content: content?.substring(0, 50_000),
    });
  }

  const tree = buildFileTree(files.filter(f => !f.isDirectory));
  const totalSize = files.reduce((sum, f) => sum + (f.size || 0), 0);
  const fileCount = files.filter(f => !f.isDirectory).length;
  const dirCount  = files.filter(f => f.isDirectory).length;

  res.json({
    success: true,
    fileName,
    fileType: ext,
    totalFiles: fileCount,
    totalDirectories: dirCount,
    totalSize,
    tree,
    files: files.filter(f => !f.isDirectory).slice(0, 500),
  });
}

// ─── POST /api/files/extract-archive ─────────────────────────────────
// Accept both FormData and JSON
router.post("/files/extract-archive", upload.single("file"), async (req: Request, res: Response) => {
  try {
    // FormData upload (from AppBuilder)
    if (req.file) {
      await extractZip(req.file.buffer, req.file.originalname, res);
      return;
    }

    // JSON body fallback (base64)
    const { fileData, fileName } = req.body as { fileData?: string; fileName?: string };
    if (!fileData || !fileName) {
      res.status(400).json({ error: "file or fileData + fileName required" });
      return;
    }
    const buffer = Buffer.from(fileData, "base64");
    await extractZip(buffer, fileName, res);
  } catch (e: any) {
    res.status(500).json({ error: `فشل فك ضغط الملف: ${e.message || "خطأ غير معروف"}` });
  }
});

function buildFileTree(
  files: { path: string; name: string; size: number }[]
): object[] {
  const root: Map<string, any> = new Map();

  for (const file of files) {
    const parts = file.path.split("/");
    let current = root;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!current.has(parts[i])) {
        current.set(parts[i], { type: "folder", name: parts[i], children: new Map() });
      }
      current = current.get(parts[i]).children;
    }
    const fname = parts[parts.length - 1];
    if (fname) {
      current.set(fname, { type: "file", name: fname, size: file.size, path: file.path });
    }
  }

  function toArray(map: Map<string, any>): any[] {
    return Array.from(map.values()).map(node => {
      if (node.type === "folder" && node.children instanceof Map) {
        return { ...node, children: toArray(node.children) };
      }
      return node;
    });
  }

  return toArray(root);
}

export default router;
