/**
 * Office Suite Routes
 * POST /api/office/generate-pptx
 * POST /api/office/generate-report
 * POST /api/office/convert
 * POST /api/office/process-excel
 * POST /api/office/run-tool
 * POST /api/office/text-to-docx
 */
import { Router } from "express";
import { generatePresentation } from "../hayo/services/presentation-generator.js";
import { generateReport } from "../hayo/services/report-generator.js";
import { convertFile, getSupportedConversions } from "../hayo/services/file-converter.js";
import { callOfficeAI, callPowerAI } from "../hayo/providers.js";

const router = Router();

// ─── POST /api/office/generate-pptx ──────────────────────────────────
router.post("/office/generate-pptx", async (req, res) => {
  const {
    topic,
    slideCount = 10,
    style = "professional",
    language = "ar",
    details = "",
  } = req.body as {
    topic: string;
    slideCount?: number;
    style?: string;
    language?: string;
    details?: string;
  };

  if (!topic) {
    res.status(400).json({ error: "topic required" });
    return;
  }

  try {
    const buffer = await generatePresentation(topic, slideCount, style as any, language, details);
    const filename = `${topic.substring(0, 30).replace(/[^\w\u0600-\u06FF]/g, "_")}.pptx`;
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.presentationml.presentation");
    res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(filename)}"`);
    res.send(buffer);
  } catch (e: any) {
    res.status(500).json({ error: e.message || "فشل إنشاء العرض التقديمي" });
  }
});

// ─── POST /api/office/generate-report ────────────────────────────────
router.post("/office/generate-report", async (req, res) => {
  const {
    topic,
    type = "business",
    language = "ar",
    pageCount = 5,
    details = "",
  } = req.body as {
    topic: string;
    type?: "business" | "academic" | "technical";
    language?: string;
    pageCount?: number;
    details?: string;
  };

  if (!topic) {
    res.status(400).json({ error: "topic required" });
    return;
  }

  try {
    const buffer = await generateReport(topic, type as any, language, pageCount, details);
    const filename = `تقرير-${topic.substring(0, 25).replace(/[^\w\u0600-\u06FF]/g, "_")}.docx`;
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(filename)}"`);
    res.send(buffer);
  } catch (e: any) {
    res.status(500).json({ error: e.message || "فشل إنشاء التقرير" });
  }
});

// ─── POST /api/office/convert ─────────────────────────────────────────
router.post("/office/convert", async (req, res) => {
  const { fileData, fileName, targetFormat } = req.body as {
    fileData: string;       // base64
    fileName: string;
    targetFormat: string;
  };

  if (!fileData || !fileName || !targetFormat) {
    res.status(400).json({ error: "fileData, fileName, and targetFormat required" });
    return;
  }

  try {
    const buffer = Buffer.from(fileData, "base64");
    const result = await convertFile(buffer, fileName, targetFormat);
    const outName = `${fileName.split(".")[0]}.${targetFormat}`;
    res.setHeader("Content-Type", getMimeType(targetFormat));
    res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(outName)}"`);
    res.send(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message || "فشل تحويل الملف" });
  }
});

// ─── GET /api/office/conversions — list supported formats ─────────────
router.get("/office/conversions", (_req, res) => {
  res.json(getSupportedConversions());
});

// ─── POST /api/office/process-excel ──────────────────────────────────
router.post("/office/process-excel", async (req, res) => {
  const { fileData, fileName, operation, query } = req.body as {
    fileData: string;
    fileName: string;
    operation: "analyze" | "query" | "clean" | "chart";
    query?: string;
  };

  if (!fileData || !fileName) {
    res.status(400).json({ error: "fileData and fileName required" });
    return;
  }

  try {
    const xlsx = await import("xlsx");
    const buffer = Buffer.from(fileData, "base64");
    const workbook = xlsx.read(buffer, { type: "buffer" });
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const data = xlsx.utils.sheet_to_json(sheet, { header: 1 }) as any[][];
    const headers = data[0] || [];
    const rows = data.slice(1);
    const preview = data.slice(0, 6);

    const summaryText = `Excel file: ${fileName}\nSheets: ${workbook.SheetNames.join(", ")}\nColumns (${headers.length}): ${headers.join(", ")}\nRows: ${rows.length}\nSample:\n${preview.map(r => r.join(" | ")).join("\n")}`;

    if (operation === "analyze" || operation === "query") {
      const q = query || "حلل هذا الملف وأعط ملخصاً مفيداً عن البيانات";
      const result = await callOfficeAI(
        "أنت محلل بيانات Excel خبير. قدّم تحليلاً مفيداً وموجزاً بالعربية.",
        `${summaryText}\n\nالطلب: ${q}`,
        4096
      );
      res.json({ analysis: result, summary: summaryText, rowCount: rows.length, colCount: headers.length });
    } else {
      res.json({ summary: summaryText, rowCount: rows.length, colCount: headers.length, headers, preview });
    }
  } catch (e: any) {
    res.status(500).json({ error: e.message || "فشل معالجة ملف Excel" });
  }
});

// ─── POST /api/office/text-to-docx ───────────────────────────────────
router.post("/office/text-to-docx", async (req, res) => {
  const { text, title = "مستند", language = "ar" } = req.body as {
    text: string;
    title?: string;
    language?: string;
  };

  if (!text) {
    res.status(400).json({ error: "text required" });
    return;
  }

  try {
    const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType } = await import("docx");
    const isAr = language === "ar";
    const paragraphs = text.split(/\n+/).filter(p => p.trim());

    const docParagraphs = [
      new Paragraph({
        children: [new TextRun({ text: title, bold: true, size: 36 })],
        heading: HeadingLevel.HEADING_1,
        alignment: isAr ? AlignmentType.RIGHT : AlignmentType.LEFT,
      }),
      new Paragraph({ children: [] }),
      ...paragraphs.map(p => {
        const isHeading = p.startsWith("##") || p.startsWith("#");
        const content = p.replace(/^#+\s*/, "");
        return new Paragraph({
          children: [new TextRun({ text: content, bold: isHeading, size: isHeading ? 28 : 24 })],
          heading: isHeading ? HeadingLevel.HEADING_2 : undefined,
          alignment: isAr ? AlignmentType.RIGHT : AlignmentType.LEFT,
        });
      }),
    ];

    const doc = new Document({
      sections: [{ properties: {}, children: docParagraphs }],
    });

    const buffer = await Packer.toBuffer(doc);
    const filename = `${title.substring(0, 30)}.docx`;
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(filename)}"`);
    res.send(buffer);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/office/run-tool — General AI office tool ───────────────
router.post("/office/run-tool", async (req, res) => {
  const { tool, input, context } = req.body as {
    tool: string;
    input: string;
    context?: string;
  };

  if (!tool || !input) {
    res.status(400).json({ error: "tool and input required" });
    return;
  }

  const toolPrompts: Record<string, string> = {
    summarize:   "أنت متخصص في تلخيص النصوص. قدّم ملخصاً واضحاً ومنظماً.",
    translate:   "أنت مترجم محترف. ترجم النص بدقة مع الحفاظ على المعنى والأسلوب.",
    proofread:   "أنت محرر لغوي متخصص. راجع النص وصحح الأخطاء النحوية والإملائية.",
    expand:      "أنت كاتب محترف. وسّع النص مع الحفاظ على الأسلوب وإضافة تفاصيل مفيدة.",
    formal:      "أنت كاتب أعمال. حوّل النص إلى أسلوب رسمي ومهني.",
    bullets:     "حوّل النص إلى نقاط واضحة ومنظمة.",
    email:       "أنت كاتب بريد إلكتروني محترف. اكتب بريداً إلكترونياً احترافياً.",
    presentation:"أنت خبير عروض تقديمية. حوّل المحتوى إلى نقاط للشرائح.",
  };

  const systemPrompt = toolPrompts[tool] || "أنت مساعد كتابة محترف. ساعد في معالجة النص المعطى.";

  try {
    const result = await callOfficeAI(
      systemPrompt,
      context ? `السياق: ${context}\n\nالنص: ${input}` : input,
      4096
    );
    res.json({ result, tool });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

function getMimeType(ext: string): string {
  const map: Record<string, string> = {
    pdf:  "application/pdf",
    docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    csv:  "text/csv",
    txt:  "text/plain",
    html: "text/html",
    json: "application/json",
    md:   "text/markdown",
    png:  "image/png",
    jpg:  "image/jpeg",
  };
  return map[ext] || "application/octet-stream";
}

export default router;
