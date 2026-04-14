/**
 * Studies Routes — 7 study categories with AI generation + export
 * POST /api/studies/generate
 * POST /api/studies/follow-up
 * POST /api/studies/export-docx
 */
import { Router } from "express";
import { callPowerAI, callOfficeAI } from "../hayo/providers.js";

const router = Router();

type StudyCategory =
  | "engineering"
  | "commerce"
  | "investment"
  | "medical"
  | "tech"
  | "agriculture"
  | "general";

const CATEGORY_PROMPTS: Record<StudyCategory, { system: string; label: string }> = {
  engineering: {
    label: "دراسة هندسية",
    system: `أنت مهندس استشاري أول ومحلل مشاريع هندسية. أعد دراسة هندسية شاملة تشمل:
- التصميم المقترح والمواصفات التقنية
- المواد والتقنيات المطلوبة
- الجدول الزمني والمراحل التنفيذية
- الميزانية التقديرية (بالدولار)
- متطلبات الترخيص والمعايير
- مخاطر المشروع والحلول
استخدم أرقام وإحصائيات حقيقية. أجب بالعربية بتنسيق منظم.`,
  },
  commerce: {
    label: "دراسة تجارية",
    system: `أنت خبير تجاري ومستشار أعمال. أعد دراسة تجارية شاملة تشمل:
- تحليل السوق والمنافسين (Porter's 5 Forces)
- الجمهور المستهدف وحجم السوق
- نموذج الأعمال والإيرادات
- استراتيجية التسويق والمبيعات
- الخطة المالية وتوقعات الأرباح (3 سنوات)
- نقاط القوة والضعف (SWOT)
استخدم أرقام وإحصائيات حقيقية. أجب بالعربية.`,
  },
  investment: {
    label: "دراسة جدوى",
    system: `أنت محلل مالي ومستشار استثماري. أعد دراسة جدوى اقتصادية شاملة تشمل:
- ملخص تنفيذي
- تكاليف الإنشاء والتشغيل
- مصادر التمويل المقترحة
- التدفقات النقدية المتوقعة (5 سنوات)
- نقطة التعادل (Break-even)
- معدل العائد على الاستثمار (ROI & IRR)
- تحليل المخاطر وسيناريوهات متعددة
استخدم أرقام دقيقة وجداول مالية. أجب بالعربية.`,
  },
  medical: {
    label: "دراسة طبية",
    system: `أنت طبيب متخصص وباحث طبي. أعد دراسة طبية شاملة تشمل:
- نظرة عامة طبية بالأدلة العلمية
- الإحصائيات والأبحاث الحديثة (مع المصادر)
- التشخيص والأعراض والعلاج
- توصيات طبية حديثة
- الإجراءات الوقائية
ملاحظة: للأغراض التعليمية فقط. أجب بالعربية.`,
  },
  tech: {
    label: "دراسة تقنية",
    system: `أنت خبير تقني ومستشار IT. أعد دراسة تقنية شاملة تشمل:
- الحل التقني المقترح ومعمارية النظام
- التقنيات والأدوات المستخدمة
- متطلبات البنية التحتية
- الأمان والخصوصية
- خطة التطوير والتكاليف
- مقارنة البدائل التقنية
أجب بالعربية مع مصطلحات تقنية دقيقة.`,
  },
  agriculture: {
    label: "دراسة زراعية",
    system: `أنت مهندس زراعي ومستشار للمشاريع الزراعية. أعد دراسة زراعية شاملة تشمل:
- المحصول/المنتج وظروف النمو المثالية
- المساحة والتربة والمناخ المناسب
- التكاليف التشغيلية (بذور، ري، أسمدة، عمالة)
- الإنتاجية المتوقعة والأسعار السوقية
- الجدوى الاقتصادية وعائد الاستثمار
- التحديات والحلول المقترحة
أجب بالعربية بأرقام حقيقية.`,
  },
  general: {
    label: "دراسة عامة",
    system: `أنت باحث ومستشار متخصص. أعد دراسة شاملة ومفصلة تغطي:
- مقدمة وخلفية الموضوع
- التحليل الشامل والنقاط الرئيسية
- البيانات والإحصائيات الداعمة
- المقارنات والسياق العام
- الخلاصة والتوصيات العملية
أجب بالعربية بأسلوب أكاديمي مهني.`,
  },
};

// ─── POST /api/studies/generate ──────────────────────────────────────
router.post("/studies/generate", async (req, res) => {
  const {
    category = "general",
    userInput,
    detailLevel = "detailed",
    additionalContext = "",
  } = req.body as {
    category?: string;
    userInput: string;
    detailLevel?: "brief" | "detailed" | "comprehensive";
    additionalContext?: string;
  };

  if (!userInput) {
    res.status(400).json({ error: "userInput required" });
    return;
  }

  const cat = (category as StudyCategory) in CATEGORY_PROMPTS
    ? (category as StudyCategory)
    : "general";

  const { system, label } = CATEGORY_PROMPTS[cat];
  const maxTokens = detailLevel === "brief" ? 3000 : detailLevel === "comprehensive" ? 12000 : 8000;

  const userPrompt = `أعد ${label} شاملة عن:\n${userInput}${additionalContext ? `\n\nمعلومات إضافية:\n${additionalContext}` : ""}

مستوى التفصيل: ${detailLevel === "brief" ? "موجز" : detailLevel === "comprehensive" ? "شامل جداً" : "مفصل"}
يجب أن تكون الدراسة احترافية وجاهزة للعرض.`;

  try {
    const result = await callPowerAI(system, userPrompt, maxTokens);
    res.json({
      study: result.content,
      category: cat,
      label,
      modelUsed: result.modelUsed,
      wordCount: result.content.split(/\s+/).length,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/studies/follow-up ─────────────────────────────────────
router.post("/studies/follow-up", async (req, res) => {
  const { studyContent, question, category = "general" } = req.body as {
    studyContent: string;
    question: string;
    category?: string;
  };

  if (!studyContent || !question) {
    res.status(400).json({ error: "studyContent and question required" });
    return;
  }

  try {
    const result = await callPowerAI(
      `أنت خبير في تحليل الدراسات والأبحاث. لديك الدراسة التالية وتجيب على أسئلة المستخدم بشكل مفصل ومدعوم بالأدلة.`,
      `الدراسة:\n${studyContent.substring(0, 6000)}\n\nالسؤال: ${question}\n\nأجب بشكل مفصل ومدعوم بمعلومات من الدراسة أو من معرفتك العامة.`,
      4096
    );

    res.json({
      answer: result.content,
      model: result.modelUsed,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/studies/export-docx ───────────────────────────────────
router.post("/studies/export-docx", async (req, res) => {
  const { content, title = "دراسة", category = "general" } = req.body as {
    content: string;
    title?: string;
    category?: string;
  };

  if (!content) {
    res.status(400).json({ error: "content required" });
    return;
  }

  try {
    const {
      Document, Packer, Paragraph, TextRun, HeadingLevel,
      AlignmentType, BorderStyle, TableRow, TableCell, Table, WidthType,
    } = await import("docx");

    const isAr = true;
    const lines = content.split("\n");
    const docChildren: any[] = [];

    // Title
    docChildren.push(
      new Paragraph({
        children: [new TextRun({ text: title, bold: true, size: 40, color: "2563EB" })],
        heading: HeadingLevel.HEADING_1,
        alignment: AlignmentType.CENTER,
      }),
      new Paragraph({ children: [new TextRun({ text: "", size: 24 })] })
    );

    for (const line of lines) {
      if (!line.trim()) {
        docChildren.push(new Paragraph({ children: [] }));
        continue;
      }

      if (line.startsWith("## ") || line.startsWith("# ")) {
        const text = line.replace(/^#+\s*/, "");
        docChildren.push(
          new Paragraph({
            children: [new TextRun({ text, bold: true, size: 30, color: "1E40AF" })],
            heading: HeadingLevel.HEADING_2,
            alignment: AlignmentType.RIGHT,
          })
        );
      } else if (line.startsWith("### ")) {
        const text = line.replace(/^###\s*/, "");
        docChildren.push(
          new Paragraph({
            children: [new TextRun({ text, bold: true, size: 26, color: "3B82F6" })],
            heading: HeadingLevel.HEADING_3,
            alignment: AlignmentType.RIGHT,
          })
        );
      } else if (line.startsWith("- ") || line.startsWith("• ")) {
        const text = line.replace(/^[-•]\s*/, "");
        docChildren.push(
          new Paragraph({
            children: [new TextRun({ text: `• ${text}`, size: 24 })],
            alignment: AlignmentType.RIGHT,
            indent: { right: 400 },
          })
        );
      } else {
        docChildren.push(
          new Paragraph({
            children: [new TextRun({ text: line, size: 24 })],
            alignment: AlignmentType.RIGHT,
          })
        );
      }
    }

    const doc = new Document({
      sections: [{
        properties: {},
        children: docChildren,
      }],
    });

    const buffer = await Packer.toBuffer(doc);
    const filename = `${title.substring(0, 30).replace(/[^\w\u0600-\u06FF]/g, "_")}.docx`;
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(filename)}"`);
    res.send(buffer);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

export default router;
