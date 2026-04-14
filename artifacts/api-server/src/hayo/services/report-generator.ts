/**
 * Word Report Generator — Markdown-based, fast generation with Haiku
 * AI generates markdown text → backend converts to rich DOCX
 */
import { callOfficeAI } from "../providers";

export async function generateReport(
  topic: string,
  type: "business" | "academic" | "technical" = "business",
  language: string = "ar",
  pageCount: number = 5,
  details: string = ""
): Promise<Buffer> {
  const isAr = language === "ar";
  const lang = isAr ? "Arabic" : "English";

  const detailsSection = details.trim()
    ? `\n\nAdditional data and notes from user (incorporate these into the report):\n${details}`
    : "";

  const prompt = `اكتب تقريراً ${type === "business" ? "تجارياً" : type === "academic" ? "أكاديمياً" : "تقنياً"} احترافياً بـ${lang} عن: "${topic}".${detailsSection}

استخدم تنسيق Markdown: ## للأقسام الرئيسية، ### للأقسام الفرعية، **عريض** للمصطلحات المهمة، - للنقاط.

المطلوب:
1. # عنوان التقرير
2. ## الملخص التنفيذي (فقرة شاملة 80-100 كلمة)
3. ${Math.max(4, pageCount)} أقسام رئيسية (##) — كل قسم يحتوي:
   - فقرة مفصلة (60-80 كلمة) مع حقائق وإحصائيات حقيقية
   - 4-6 نقاط تفصيلية (- نقطة) كل منها جملة كاملة 15+ كلمة
   - قسمان على الأقل يحتويان: **[STAT: القيمة | الوصف]** مع إحصائية حقيقية
   - أقسام فرعية (###) عند الحاجة
4. ## التوصيات والخطوات التالية (5 توصيات عملية مع جدول زمني)
5. ## الخلاصة (فقرة 50-60 كلمة)

اكتب ${pageCount * 350} كلمة تقريباً. استخدم إحصائيات ودراسات حقيقية عن "${topic}".
ابدأ مباشرة بـ # العنوان. لا تضف تعليقات أو شروحات خارج التقرير.`;

  const aiContent = await callOfficeAI(
    `أنت كاتب تقارير محترف على مستوى عالمي. اكتب تقارير شاملة ومفصلة بـ${lang} مع إحصائيات حقيقية وتحليلات عميقة وتوصيات عملية. استخدم تنسيق Markdown نظيف.`,
    prompt,
    8192,
    "claude-sonnet-4-6"
  );

  return buildDocxFromMarkdown(aiContent || "", topic, type, language, isAr);
}

async function buildDocxFromMarkdown(
  markdown: string,
  topic: string,
  type: string,
  language: string,
  isAr: boolean
): Promise<Buffer> {
  const {
    Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
    ShadingType,
  } = await import("docx");

  /** Parse inline **bold** and return TextRun array */
  function parseInlineRuns(text: string): any[] {
    const runs: any[] = [];
    const parts = text.split(/(\*\*[^*]+\*\*)/g);
    for (const part of parts) {
      if (!part) continue;
      if (part.startsWith("**") && part.endsWith("**")) {
        runs.push(new TextRun({ text: part.slice(2, -2), size: 22, font: "Arial", bold: true }));
      } else {
        runs.push(new TextRun({ text: part, size: 22, font: "Arial" }));
      }
    }
    return runs;
  }

  const typeLabels: Record<string, string> = {
    business: isAr ? "تجاري" : "Business",
    academic: isAr ? "أكاديمي" : "Academic",
    technical: isAr ? "تقني" : "Technical",
  };
  const typeLabel = typeLabels[type] || type;
  const dateStr = new Date().toLocaleDateString(isAr ? "ar-SA" : "en-US", {
    year: "numeric", month: "long", day: "numeric",
  });

  const children: any[] = [];
  const align = isAr ? AlignmentType.RIGHT : AlignmentType.LEFT;

  // ── Cover Page ──
  children.push(
    new Paragraph({ spacing: { before: 2000, after: 300 } }),
    new Paragraph({
      children: [new TextRun({ text: topic, bold: true, size: 52, font: "Arial", color: "1a1a2e" })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 250 },
    }),
    new Paragraph({
      children: [new TextRun({ text: `${typeLabel} | ${dateStr}`, size: 26, font: "Arial", color: "6366f1" })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 180 },
    }),
    new Paragraph({
      children: [new TextRun({ text: isAr ? "أُعِدَّ بواسطة HAYO AI" : "Prepared by HAYO AI", size: 22, font: "Arial", color: "888888" })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 800 },
    }),
    new Paragraph({
      children: [new TextRun({ text: "─".repeat(55), color: "6366f1", size: 14, font: "Arial" })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 800 },
    }),
  );

  // ── Parse Markdown ──
  const lines = markdown.split("\n");

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line) {
      children.push(new Paragraph({ spacing: { after: 120 } }));
      continue;
    }

    // H1
    if (line.startsWith("# ")) {
      const text = stripInlineMarkdown(line.slice(2));
      children.push(new Paragraph({
        children: [new TextRun({ text, bold: true, size: 44, font: "Arial", color: "1a1a2e" })],
        alignment: AlignmentType.CENTER,
        spacing: { before: 600, after: 300 },
      }));
      continue;
    }

    // H2
    if (line.startsWith("## ")) {
      const text = stripInlineMarkdown(line.slice(3));
      children.push(new Paragraph({
        heading: HeadingLevel.HEADING_1,
        children: [new TextRun({ text, bold: true, size: 34, font: "Arial", color: "1a1a2e" })],
        spacing: { before: 600, after: 200 },
        bidirectional: isAr,
      }));
      continue;
    }

    // H3
    if (line.startsWith("### ")) {
      const text = stripInlineMarkdown(line.slice(4));
      children.push(new Paragraph({
        heading: HeadingLevel.HEADING_2,
        children: [new TextRun({ text, bold: true, size: 26, font: "Arial", color: "374151" })],
        spacing: { before: 400, after: 150 },
        bidirectional: isAr,
      }));
      continue;
    }

    // Bullet
    if (line.startsWith("- ") || line.startsWith("* ")) {
      const text = stripInlineMarkdown(line.slice(2));
      children.push(new Paragraph({
        children: [
          new TextRun({ text: "  ◆  ", size: 20, font: "Arial", color: "6366f1", bold: true }),
          new TextRun({ text, size: 22, font: "Arial" }),
        ],
        spacing: { after: 100 },
        alignment: align,
        bidirectional: isAr,
        indent: { left: isAr ? 0 : 360, right: isAr ? 360 : 0 },
      }));
      continue;
    }

    // Numbered list
    if (/^\d+\.\s/.test(line)) {
      const numMatch = line.match(/^(\d+)\.\s(.*)/);
      if (numMatch) {
        const num = numMatch[1];
        const text = stripInlineMarkdown(numMatch[2]);
        children.push(new Paragraph({
          children: [
            new TextRun({ text: `${num}. `, size: 22, font: "Arial", bold: true, color: "6366f1" }),
            new TextRun({ text, size: 22, font: "Arial" }),
          ],
          spacing: { after: 120 },
          alignment: align,
          bidirectional: isAr,
          indent: { left: isAr ? 0 : 360, right: isAr ? 360 : 0 },
        }));
        continue;
      }
    }

    // STAT highlight: **[STAT: value | label]**
    const statMatch = line.match(/\*\*\[STAT:\s*([^|]+)\|\s*([^\]]+)\]\*\*/);
    if (statMatch) {
      const value = statMatch[1].trim();
      const label = statMatch[2].trim();
      children.push(new Paragraph({
        children: [
          new TextRun({ text: `  ${value}  `, size: 40, font: "Arial", bold: true, color: "6366f1" }),
          new TextRun({ text: `  —  ${label}`, size: 22, font: "Arial", color: "374151" }),
        ],
        alignment: AlignmentType.CENTER,
        spacing: { before: 200, after: 200 },
        shading: { type: ShadingType.SOLID, fill: "eef0ff" },
        indent: { left: 720, right: 720 },
        bidirectional: isAr,
      }));
      continue;
    }

    // Horizontal rule
    if (line === "---" || line === "***" || line === "___") {
      children.push(new Paragraph({
        children: [new TextRun({ text: "─".repeat(55), color: "6366f1", size: 14, font: "Arial" })],
        alignment: AlignmentType.CENTER,
        spacing: { before: 200, after: 200 },
      }));
      continue;
    }

    // Regular paragraph (parse inline bold)
    const runs = parseInlineRuns(line);
    if (runs.length > 0) {
      children.push(new Paragraph({
        children: runs,
        spacing: { after: 150 },
        alignment: align,
        bidirectional: isAr,
      }));
    }
  }

  const doc = new Document({
    creator: "HAYO AI",
    title: topic,
    description: `${type} report generated by HAYO AI`,
    sections: [{
      properties: {
        page: { margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } },
      },
      children,
    }],
  });

  return Buffer.from(await Packer.toBuffer(doc));
}

/** Strip all inline markdown markers for headings */
function stripInlineMarkdown(text: string): string {
  return text.replace(/\*\*([^*]+)\*\*/g, "$1").replace(/\*([^*]+)\*/g, "$1").trim();
}
