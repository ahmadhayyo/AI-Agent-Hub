/**
 * PowerPoint Presentation Generator — Premium Quality
 * Uses PptxGenJS + AI to create rich professional slides with charts & tables
 */
import { callOfficeAI } from "../providers";

interface SlideData {
  type: "title" | "content" | "chart" | "table" | "twoCol" | "closing";
  title: string;
  subtitle?: string;
  bullets?: string[];
  detailedContent?: string;
  statBox?: { label: string; value: string; desc: string };
  chartData?: { title: string; labels: string[]; values: number[]; type: "bar" | "pie" };
  tableHeaders?: string[];
  tableRows?: (string | number)[][];
  col1?: { title: string; bullets: string[] };
  col2?: { title: string; bullets: string[] };
  notes?: string;
}

const THEMES = {
  professional: {
    bg: "0f0f1a",
    headerBg: "1a1a35",
    title: "e8e8ff",
    subtitle: "a0a0c0",
    text: "c8c8e0",
    accent: "6366f1",
    accentLight: "2d2f6b",
    accentMid: "4446a8",
    accent2: "8b5cf6",
    chartColors: ["6366f1", "8b5cf6", "a78bfa", "c4b5fd", "ddd6fe"],
    tableBg: "1e1e3a",
    tableHeader: "6366f1",
    separator: "6366f1",
  },
  creative: {
    bg: "0a0a15",
    headerBg: "1a1500",
    title: "fff7d4",
    subtitle: "e0c060",
    text: "ead89a",
    accent: "f59e0b",
    accentLight: "3d2800",
    accentMid: "7a5006",
    accent2: "d97706",
    chartColors: ["f59e0b", "d97706", "b45309", "fbbf24", "fde68a"],
    tableBg: "1a1500",
    tableHeader: "f59e0b",
    separator: "f59e0b",
  },
  academic: {
    bg: "0d1526",
    headerBg: "1a2a42",
    title: "dbeafe",
    subtitle: "93c5fd",
    text: "bfdbfe",
    accent: "3b82f6",
    accentLight: "0f2540",
    accentMid: "1e4a80",
    accent2: "2563eb",
    chartColors: ["3b82f6", "2563eb", "1d4ed8", "60a5fa", "93c5fd"],
    tableBg: "1a2a42",
    tableHeader: "3b82f6",
    separator: "3b82f6",
  },
};

export async function generatePresentation(
  topic: string,
  slideCount: number = 10,
  style: "professional" | "creative" | "academic" = "professional",
  language: string = "ar",
  details: string = ""
): Promise<Buffer> {
  const isAr = language === "ar";
  const lang = isAr ? "Arabic" : "English";
  const direction = isAr ? "right" : "left";

  const detailsSection = details.trim()
    ? `\n\nتعليمات إضافية من المستخدم (يجب تضمينها):\n${details}`
    : "";

  const prompt = `أنشئ عرضاً تقديمياً احترافياً مكون من ${slideCount} شريحة عن: "${topic}"
اللغة: ${lang} | الأسلوب: ${style}${detailsSection}

أُرجع مصفوفة JSON فقط. كل شريحة غنية بمحتوى حقيقي ومفصل.

الشرائح المطلوبة:
1. {"type":"title","title":"عنوان قوي","subtitle":"سياق مع السنة"}
2. ${slideCount - 4} شرائح محتوى: {"type":"content","title":"...","bullets":["فقرة 15+ كلمة","فقرة 15+ كلمة","فقرة 15+ كلمة","فقرة 15+ كلمة"],"statBox":{"label":"إحصائية","value":"85%","desc":"وصف"},"notes":"ملاحظات 2-3 جمل"}
3. {"type":"chart","title":"...","chartData":{"title":"...","labels":["أ","ب","ج","د","هـ","و"],"values":[45,68,82,73,91,87],"type":"bar"},"notes":""}
4. {"type":"table","title":"...","tableHeaders":["معيار","حالي","مستهدف","فجوة","أولوية"],"tableRows":[5 صفوف بيانات واقعية],"notes":""}
5. {"type":"twoCol","title":"...","col1":{"title":"التحديات","bullets":["...","...","..."]},"col2":{"title":"الحلول","bullets":["...","...","..."]}}
6. {"type":"closing","title":"الخلاصة","bullets":["توصية مع خطوات عملية","توصية مع أهداف","توصية مع جدول زمني"]}

قواعد: كل bullet = فقرة 15-25 كلمة. إحصائيات حقيقية. بيانات واقعية. كل النص بـ ${lang}. JSON فقط.`;

  const aiContent = await callOfficeAI(
    "أنت خبير عروض تقديمية. أنشئ محتوى غني ومفصل. كل نقطة فقرة كاملة. إحصائيات واقعية. JSON فقط.",
    prompt,
    8192,
    "claude-sonnet-4-6"
  );

  let slides: SlideData[];
  try {
    const cleaned = aiContent.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const match = cleaned.match(/\[[\s\S]*\]/);
    slides = JSON.parse(match ? match[0] : cleaned);
    if (!Array.isArray(slides)) throw new Error("Not array");
  } catch {
    slides = generateFallbackSlides(topic, slideCount, isAr);
  }

  const PptxGenJS = (await import("pptxgenjs")).default;
  const pres = new PptxGenJS();
  pres.layout = "LAYOUT_WIDE";
  const theme = THEMES[style] || THEMES.professional;

  for (let i = 0; i < slides.length; i++) {
    const sd = slides[i];
    const slide = pres.addSlide();
    slide.background = { color: theme.bg };

    // Slide transition (alternating effects for visual variety)
    const transitions = ["fade", "push", "wipe", "cover", "reveal"];
    try {
      (slide as any).transition = { type: transitions[i % transitions.length], speed: 1.5 };
    } catch { /* PptxGenJS version may not support transitions */ }

    // Top accent bar
    slide.addShape("rect" as any, { x: 0, y: 0, w: "100%", h: 0.1, fill: { color: theme.accent } });
    // Bottom accent bar
    slide.addShape("rect" as any, { x: 0, y: 7.4, w: "100%", h: 0.1, fill: { color: theme.accent } });

    if (sd.type === "title") {
      renderTitleSlide(slide, sd, theme, direction, topic);
    } else if (sd.type === "chart" && sd.chartData) {
      renderChartSlide(slide, sd, theme, direction);
    } else if (sd.type === "table" && sd.tableHeaders && sd.tableRows) {
      renderTableSlide(slide, sd, theme, direction, isAr);
    } else if (sd.type === "twoCol" && sd.col1 && sd.col2) {
      renderTwoColSlide(slide, sd, theme, direction, i, slides.length);
    } else if (sd.type === "closing") {
      renderClosingSlide(slide, sd, theme, direction);
    } else {
      renderContentSlide(slide, sd, theme, direction, i, slides.length);
    }

    // Speaker notes
    if (sd.notes) slide.addNotes(String(sd.notes));
  }

  const pptxData = await pres.write({ outputType: "nodebuffer" });
  return pptxData as unknown as Buffer;
}

function renderTitleSlide(slide: any, sd: SlideData, theme: any, dir: string, topic: string) {
  // Big decorative rectangle
  slide.addShape("rect" as any, { x: 0, y: 2.5, w: "100%", h: 0.006, fill: { color: theme.accent } });
  slide.addShape("rect" as any, { x: 0, y: 0, w: 0.15, h: "100%", fill: { color: theme.accent } });

  slide.addText(String(sd.title || topic), {
    x: 0.5, y: 1.2, w: 12.5, h: 2.0,
    fontSize: 40, bold: true, color: theme.title,
    align: dir as any, fontFace: "Arial",
    shadow: { type: "outer", color: theme.accent, blur: 15, offset: 3, angle: 315 },
  });

  if (sd.subtitle) {
    slide.addText(sd.subtitle, {
      x: 0.5, y: 3.4, w: 12.5, h: 0.8,
      fontSize: 20, color: theme.subtitle,
      align: dir as any, fontFace: "Arial",
    });
  }

  // Decorative circles
  slide.addShape("ellipse" as any, { x: 11, y: 5.5, w: 2, h: 2, fill: { color: theme.accentLight }, line: { color: theme.accent, width: 1 } });
  slide.addShape("ellipse" as any, { x: 11.5, y: 6, w: 1, h: 1, fill: { color: theme.accentMid } });
}

function renderContentSlide(slide: any, sd: SlideData, theme: any, dir: string, idx: number, total: number) {
  // Title
  slide.addText(String(sd.title || ""), {
    x: 0.4, y: 0.2, w: 11, h: 0.85,
    fontSize: 24, bold: true, color: theme.title,
    align: dir as any, fontFace: "Arial",
  });
  slide.addShape("rect" as any, { x: 0.4, y: 1.1, w: 4, h: 0.05, fill: { color: theme.accent } });

  const hasStatBox = sd.statBox && sd.statBox.value;
  const contentWidth = hasStatBox ? 8.5 : 12.8;

  // Bullets
  if (sd.bullets?.length) {
    const bulletTexts = sd.bullets.map((b: string) => ({
      text: `◆  ${b}\n`,
      options: {
        fontSize: 14,
        color: theme.text,
        fontFace: "Arial",
        breakLine: true,
        paraSpaceAfter: 8,
      },
    }));
    slide.addText(bulletTexts, {
      x: 0.4, y: 1.25, w: contentWidth, h: 5.8,
      valign: "top",
      align: dir as any,
    });
  }

  // Stat box
  if (hasStatBox) {
    slide.addShape("rect" as any, {
      x: 9.6, y: 1.4, w: 3.4, h: 3.0,
      fill: { color: theme.accentLight },
      line: { color: theme.accent, width: 2 },
      rectRadius: 0.15,
    });
    slide.addText(sd.statBox!.value, {
      x: 9.6, y: 1.8, w: 3.4, h: 1.0,
      fontSize: 36, bold: true, color: theme.accent,
      align: "center", fontFace: "Arial",
    });
    slide.addText(sd.statBox!.label, {
      x: 9.6, y: 2.8, w: 3.4, h: 0.5,
      fontSize: 14, bold: true, color: theme.title,
      align: "center", fontFace: "Arial",
    });
    slide.addText(sd.statBox!.desc, {
      x: 9.6, y: 3.3, w: 3.4, h: 0.8,
      fontSize: 11, color: theme.subtitle,
      align: "center", fontFace: "Arial",
    });
  }

  // Slide number
  slide.addText(`${idx} / ${total}`, {
    x: 12, y: 7.1, w: 1, h: 0.35,
    fontSize: 9, color: "555577", align: "right", fontFace: "Arial",
  });
}

function renderChartSlide(slide: any, sd: SlideData, theme: any, dir: string) {
  const cd = sd.chartData!;

  slide.addText(String(sd.title || ""), {
    x: 0.4, y: 0.2, w: 12, h: 0.85,
    fontSize: 24, bold: true, color: theme.title,
    align: dir as any, fontFace: "Arial",
  });
  slide.addShape("rect" as any, { x: 0.4, y: 1.1, w: 4, h: 0.05, fill: { color: theme.accent } });

  const chartData = [{
    name: cd.title || sd.title,
    labels: cd.labels,
    values: cd.values,
  }];

  const chartColors = theme.chartColors;

  try {
    if (cd.type === "pie") {
      slide.addChart("pie" as any, chartData, {
        x: 1, y: 1.3, w: 11, h: 5.8,
        showLegend: true,
        legendPos: "b",
        showValue: true,
        chartColors: chartColors,
        dataLabelFontSize: 12,
        legendFontSize: 12,
      });
    } else {
      slide.addChart("bar" as any, chartData, {
        x: 1, y: 1.3, w: 11, h: 5.8,
        barDir: "col",
        showValue: true,
        dataLabelFontSize: 11,
        catAxisLabelFontSize: 12,
        valAxisLabelFontSize: 11,
        chartColors: chartColors,
        showLegend: false,
        valAxisMinVal: 0,
      });
    }
  } catch {
    // Fallback: show data as text table
    const rows: any[][] = [
      cd.labels.map((l: string) => ({ text: l, options: { bold: true, color: "ffffff", fontSize: 12, fontFace: "Arial" } })),
      cd.values.map((v: number) => ({ text: String(v), options: { color: theme.text, fontSize: 14, fontFace: "Arial" } })),
    ];
    slide.addTable(rows, {
      x: 0.5, y: 2, w: 12.5, h: 2,
      color: theme.text,
      fill: theme.tableBg,
    });
  }
}

function renderTableSlide(slide: any, sd: SlideData, theme: any, dir: string, isAr: boolean) {
  slide.addText(String(sd.title || ""), {
    x: 0.4, y: 0.2, w: 12, h: 0.85,
    fontSize: 24, bold: true, color: theme.title,
    align: dir as any, fontFace: "Arial",
  });
  slide.addShape("rect" as any, { x: 0.4, y: 1.1, w: 4, h: 0.05, fill: { color: theme.accent } });

  const headers = sd.tableHeaders!;
  const rows = sd.tableRows!;

  const headerRow = headers.map(h => ({
    text: String(h),
    options: {
      bold: true,
      color: "ffffff",
      fill: theme.tableHeader,
      fontSize: 13,
      fontFace: "Arial",
      align: isAr ? "right" : "left",
    },
  }));

  const dataRows = rows.map((row, ri) =>
    row.map(cell => ({
      text: String(cell ?? ""),
      options: {
        color: theme.text,
        fill: ri % 2 === 0 ? theme.tableBg : theme.headerBg,
        fontSize: 12,
        fontFace: "Arial",
        align: isAr ? "right" : "left",
      },
    }))
  );

  const colW = 13 / headers.length;
  slide.addTable([headerRow, ...dataRows], {
    x: 0.4, y: 1.3, w: 13, h: 5.8,
    rowH: Math.min(0.6, 5.8 / (rows.length + 1)),
    colW: headers.map(() => colW),
    border: { type: "solid", color: theme.accentMid, pt: 1 },
  });
}

function renderTwoColSlide(slide: any, sd: SlideData, theme: any, dir: string, idx: number, total: number) {
  slide.addText(String(sd.title || ""), {
    x: 0.4, y: 0.2, w: 12, h: 0.85,
    fontSize: 24, bold: true, color: theme.title,
    align: dir as any, fontFace: "Arial",
  });
  slide.addShape("rect" as any, { x: 0.4, y: 1.1, w: 4, h: 0.05, fill: { color: theme.accent } });

  // Left column
  slide.addShape("rect" as any, { x: 0.3, y: 1.2, w: 6.2, h: 6.0, fill: { color: theme.accentLight }, line: { color: theme.accentMid, width: 1 }, rectRadius: 0.12 });
  slide.addText(sd.col1!.title, { x: 0.5, y: 1.35, w: 5.8, h: 0.5, fontSize: 15, bold: true, color: theme.accent, fontFace: "Arial", align: "center" });
  if (sd.col1!.bullets) {
    const col1Items = sd.col1!.bullets.map(b => ({ text: `▶ ${b}\n`, options: { fontSize: 12, color: theme.text, fontFace: "Arial", breakLine: true, paraSpaceAfter: 6 } }));
    slide.addText(col1Items, { x: 0.5, y: 1.9, w: 5.8, h: 5.1, valign: "top", align: "left" });
  }

  // Right column
  slide.addShape("rect" as any, { x: 6.9, y: 1.2, w: 6.2, h: 6.0, fill: { color: theme.headerBg }, line: { color: theme.accent2, width: 1 }, rectRadius: 0.12 });
  slide.addText(sd.col2!.title, { x: 7.1, y: 1.35, w: 5.8, h: 0.5, fontSize: 15, bold: true, color: theme.accent2, fontFace: "Arial", align: "center" });
  if (sd.col2!.bullets) {
    const col2Items = sd.col2!.bullets.map(b => ({ text: `▶ ${b}\n`, options: { fontSize: 12, color: theme.text, fontFace: "Arial", breakLine: true, paraSpaceAfter: 6 } }));
    slide.addText(col2Items, { x: 7.1, y: 1.9, w: 5.8, h: 5.1, valign: "top", align: "left" });
  }

  // Center divider
  slide.addShape("rect" as any, { x: 6.65, y: 1.5, w: 0.04, h: 5.5, fill: { color: theme.accent } });

  slide.addText(`${idx} / ${total}`, { x: 12, y: 7.1, w: 1, h: 0.35, fontSize: 9, color: "555577", align: "right", fontFace: "Arial" });
}

function renderClosingSlide(slide: any, sd: SlideData, theme: any, dir: string) {
  slide.addShape("rect" as any, { x: 0, y: 0, w: "100%", h: "100%", fill: { color: theme.accentLight } });
  slide.addShape("rect" as any, { x: 0, y: 0, w: "100%", h: 0.1, fill: { color: theme.accent } });
  slide.addShape("rect" as any, { x: 0, y: 7.4, w: "100%", h: 0.1, fill: { color: theme.accent } });

  slide.addText(String(sd.title || "شكراً"), {
    x: 0.5, y: 1.0, w: 12.5, h: 1.5,
    fontSize: 44, bold: true, color: theme.title,
    align: "center", fontFace: "Arial",
  });

  if (sd.bullets?.length) {
    const items = sd.bullets.map(b => ({
      text: `✓  ${b}\n`,
      options: { fontSize: 16, color: theme.text, fontFace: "Arial", breakLine: true, paraSpaceAfter: 10 },
    }));
    slide.addText(items, {
      x: 1.5, y: 2.8, w: 10.5, h: 4.0,
      valign: "top", align: dir as any,
    });
  }
}

function generateFallbackSlides(topic: string, count: number, isAr: boolean): SlideData[] {
  const t = (ar: string, en: string) => isAr ? ar : en;
  return ([
    { type: "title" as const, title: topic, subtitle: t(`عرض احترافي - ${new Date().getFullYear()}`, `Professional Presentation - ${new Date().getFullYear()}`), notes: t("افتح بتعريف قوي عن الموضوع", "Open with a strong introduction") },
    { type: "content", title: t("المقدمة", "Introduction"), bullets: [t("نظرة شاملة على الموضوع وأهميته في السياق الحالي", "Comprehensive overview of the topic and its importance in current context"), t("الأهداف الرئيسية التي يسعى هذا العرض لتحقيقها", "Main objectives this presentation aims to achieve"), t("المنهجية المُتبعة في البحث والتحليل", "Methodology used in research and analysis"), t("الجمهور المستهدف والاستفادة المتوقعة", "Target audience and expected benefits")], notes: t("ابدأ بقصة أو إحصائية مثيرة", "Start with an engaging story or statistic") },
    { type: "chart", title: t("بيانات وإحصائيات", "Data & Statistics"), chartData: { title: t("نمو القطاع", "Sector Growth"), labels: [t("2020","2020"), t("2021","2021"), t("2022","2022"), t("2023","2023"), t("2024","2024")], values: [35, 48, 62, 79, 95], type: "bar" }, notes: t("اشرح الاتجاه التصاعدي", "Explain the upward trend") },
    { type: "content", title: t("المحاور الرئيسية", "Key Points"), bullets: [t("أولى النقاط الجوهرية التي يجب فهمها بعمق", "First key point that must be deeply understood"), t("ثاني المحاور الأساسية وتأثيرها على النتائج", "Second key area and its impact on outcomes"), t("ثالث العناصر المهمة في هذا السياق", "Third important element in this context"), t("الروابط والتأثيرات المتبادلة بين المحاور", "Connections and interactions between key areas")], statBox: { label: t("نسبة النجاح", "Success Rate"), value: "87%", desc: t("بناءً على أحدث الدراسات", "Based on latest studies") }, notes: "" },
    { type: "table", title: t("جدول البيانات المقارنة", "Comparative Data Table"), tableHeaders: [t("المعيار","Metric"), t("الوضع الحالي","Current"), t("المستهدف","Target"), t("الفجوة","Gap"), t("الأولوية","Priority")], tableRows: [[t("الكفاءة","Efficiency"), "65%", "90%", "25%", t("عالية","High")], [t("الجودة","Quality"), "78%", "95%", "17%", t("متوسطة","Medium")], [t("السرعة","Speed"), "70%", "88%", "18%", t("عالية","High")], [t("التكلفة","Cost"), "$120K", "$95K", "$25K", t("حرجة","Critical")]], notes: "" },
    { type: "twoCol", title: t("المقارنة والتحليل", "Comparison & Analysis"), col1: { title: t("النقاط القوية", "Strengths"), bullets: [t("قدرات متميزة ومثبتة في السوق", "Proven capabilities in the market"), t("فريق خبرة عالية ومتخصص", "Highly specialized expert team"), t("بنية تحتية متطورة وحديثة", "Advanced modern infrastructure")] }, col2: { title: t("فرص التحسين", "Improvement Areas"), bullets: [t("إمكانات نمو واسعة في أسواق جديدة", "Vast growth potential in new markets"), t("تكنولوجيا يمكن تطويرها وتوسيعها", "Technology that can be enhanced"), t("شراكات استراتيجية محتملة", "Potential strategic partnerships")] }, notes: "" },
    { type: "closing", title: t("شكراً لكم", "Thank You"), bullets: [t("نقطة الخلاصة الأولى: أهمية التحرك الآن", "Key takeaway 1: Importance of acting now"), t("نقطة الخلاصة الثانية: الفرص المتاحة", "Key takeaway 2: Available opportunities"), t("نقطة الخلاصة الثالثة: الخطوات التالية المقترحة", "Key takeaway 3: Suggested next steps")], notes: "" },
  ] as SlideData[]).slice(0, count);
}
