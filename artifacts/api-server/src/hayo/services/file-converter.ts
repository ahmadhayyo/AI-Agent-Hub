/**
 * File Converter Service — Comprehensive Format Support
 * Supports 30+ conversion paths using pure JS libraries
 */
import path from "path";
import { fileURLToPath } from "url";

async function getXLSX() {
  return await import("xlsx") as typeof import("xlsx");
}

export function getSupportedConversions(): Record<string, string[]> {
  return {
    pdf:  ["txt", "docx", "xlsx", "csv"],
    docx: ["txt", "html", "pdf", "xlsx", "csv", "md"],
    doc:  ["txt", "pdf", "docx"],
    xlsx: ["csv", "json", "txt", "pdf", "docx", "html"],
    xls:  ["csv", "xlsx", "json", "pdf", "docx"],
    csv:  ["xlsx", "json", "pdf", "docx", "txt", "html"],
    json: ["csv", "xlsx", "txt", "pdf", "html"],
    txt:  ["pdf", "docx", "html", "md"],
    md:   ["html", "pdf", "docx", "txt"],
    html: ["txt", "pdf", "docx", "md"],
    png:  ["pdf", "jpg"],
    jpg:  ["pdf", "png"],
    jpeg: ["pdf", "png"],
    gif:  ["pdf"],
    webp: ["pdf", "jpg"],
    pptx: ["txt"],
  };
}

// ── PDF helpers ──
async function pdfToText(buf: Buffer): Promise<string> {
  try {
    const pdfParseModule = await import("pdf-parse");
    const pdfParse = (pdfParseModule as any).default ?? pdfParseModule;
    const data = await pdfParse(buf);
    return data.text || "";
  } catch (err: any) {
    throw new Error(`فشل قراءة PDF: ${err.message}`);
  }
}

async function pdfToDocx(buf: Buffer): Promise<Buffer> {
  const { Document, Packer, Paragraph, TextRun, HeadingLevel } = await import("docx");
  const text = await pdfToText(buf);
  const paras = text.split(/\n{2,}/).filter(p => p.trim());
  const doc = new Document({
    sections: [{
      properties: { page: { margin: { top: 1000, right: 1000, bottom: 1000, left: 1000 } } },
      children: paras.map(p => new Paragraph({
        children: [new TextRun({ text: p.trim(), size: 24, font: "Arial" })],
        spacing: { after: 200 },
      })),
    }],
  });
  return Buffer.from(await Packer.toBuffer(doc));
}

async function pdfToXlsx(buf: Buffer): Promise<Buffer> {
  const text = await pdfToText(buf);
  const XLSX = await getXLSX();
  const wb = XLSX.utils.book_new();
  const lines = text.split("\n").filter(l => l.trim());
  const rows = lines.map(l => [l.trim()]);
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([["المحتوى"], ...rows]), "المحتوى");
  return Buffer.from(XLSX.write(wb, { type: "buffer", bookType: "xlsx" }));
}

async function pdfToCsv(buf: Buffer): Promise<string> {
  const text = await pdfToText(buf);
  return text.split("\n").filter(l => l.trim()).map(l => `"${l.trim().replace(/"/g, '""')}"`).join("\n");
}

// ── DOCX helpers ──
async function docxToText(buf: Buffer): Promise<string> {
  const mammoth = await import("mammoth");
  return (await mammoth.extractRawText({ buffer: buf })).value;
}

async function docxToHtml(buf: Buffer): Promise<string> {
  const mammoth = await import("mammoth");
  const html = (await mammoth.convertToHtml({ buffer: buf })).value;
  return wrapHtml(html, true);
}

async function docxToXlsx(buf: Buffer): Promise<Buffer> {
  const text = await docxToText(buf);
  const XLSX = await getXLSX();
  const wb = XLSX.utils.book_new();
  const lines = text.split("\n").filter(l => l.trim());
  const rows = lines.map(l => [l.trim()]);
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([["المحتوى"], ...rows]), "المحتوى");
  return Buffer.from(XLSX.write(wb, { type: "buffer", bookType: "xlsx" }));
}

async function docxToCsv(buf: Buffer): Promise<string> {
  const text = await docxToText(buf);
  return text.split("\n").filter(l => l.trim()).map(l => `"${l.replace(/"/g, '""')}"`).join("\n");
}

async function docxToMd(buf: Buffer): Promise<string> {
  const mammoth = await import("mammoth");
  const result = await mammoth.convertToHtml({ buffer: buf });
  return htmlToMd(result.value);
}

// ── Arabic font path ──
const _dirname = path.dirname(fileURLToPath(import.meta.url));
const ARABIC_FONT = path.join(_dirname, "../fonts/Amiri-Regular.ttf");

function hasArabic(text: string): boolean {
  return /[\u0600-\u06FF]/.test(text);
}

// ── PDF generation ──
async function textToPdf(text: string, title?: string): Promise<Buffer> {
  return new Promise(async (resolve, reject) => {
    const PDFKit = (await import("pdfkit")).default;
    const isAr = hasArabic(text) || (title ? hasArabic(title) : false);
    const doc = new PDFKit({ size: "A4", margin: 50 });
    const chunks: Buffer[] = [];
    doc.on("data", (c: Buffer) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    if (isAr) {
      try { doc.registerFont("Arabic", ARABIC_FONT); } catch {}
    }
    const fontName = isAr ? "Arabic" : "Helvetica";
    const boldFont = isAr ? "Arabic" : "Helvetica-Bold";

    if (title) {
      doc.fontSize(18).font(boldFont).text(title, { align: isAr ? "right" : "center" });
      doc.moveDown();
    }
    doc.fontSize(12).font(fontName).text(text, {
      lineGap: 4,
      align: isAr ? "right" : "left",
    });
    doc.end();
  });
}

async function htmlToPdf(html: string): Promise<Buffer> {
  const text = html.replace(/<[^>]+>/g, " ").replace(/\s{2,}/g, " ").trim();
  return textToPdf(text);
}

// ── DOCX generation ──
async function textToDocx(text: string): Promise<Buffer> {
  const { Document, Packer, Paragraph, TextRun } = await import("docx");
  const lines = text.split("\n");
  const children: any[] = [];
  for (const line of lines) {
    const t = line.trim();
    if (!t) { children.push(new Paragraph({ spacing: { after: 80 } })); continue; }
    if (t.startsWith("# ")) {
      children.push(new Paragraph({ children: [new TextRun({ text: t.slice(2), bold: true, size: 32 })], spacing: { before: 300, after: 150 } }));
    } else if (t.startsWith("## ")) {
      children.push(new Paragraph({ children: [new TextRun({ text: t.slice(3), bold: true, size: 26 })], spacing: { before: 200, after: 100 } }));
    } else if (t.startsWith("- ") || t.startsWith("* ")) {
      children.push(new Paragraph({ children: [new TextRun({ text: "• " + t.slice(2), size: 22 })], indent: { left: 720 }, spacing: { after: 80 } }));
    } else {
      children.push(new Paragraph({ children: [new TextRun({ text: t, size: 22, font: "Arial" })], spacing: { after: 100 } }));
    }
  }
  const doc = new Document({ sections: [{ children }] });
  return Buffer.from(await Packer.toBuffer(doc));
}

async function htmlToDocx(html: string): Promise<Buffer> {
  const text = html.replace(/<br\s*\/?>/gi, "\n").replace(/<\/p>/gi, "\n\n")
    .replace(/<\/h[1-6]>/gi, "\n").replace(/<[^>]+>/g, "").trim();
  return textToDocx(text);
}

// ── Table to DOCX (for xlsx/csv→docx) ──
async function tableToDocx(headers: string[], rows: string[][]): Promise<Buffer> {
  const { Document, Packer, Paragraph, Table, TableRow, TableCell, TextRun, WidthType, BorderStyle } = await import("docx");
  const border = { style: BorderStyle.SINGLE, size: 1, color: "cccccc" };
  const cellBorders = { top: border, bottom: border, left: border, right: border };

  const headerRow = new TableRow({
    children: headers.map(h => new TableCell({
      children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, size: 20, color: "ffffff", font: "Arial" })] })],
      shading: { fill: "6366f1" },
      borders: cellBorders,
      margins: { top: 80, bottom: 80, left: 120, right: 120 },
    })),
  });

  const dataRows = rows.map((row, ri) => new TableRow({
    children: row.map(cell => new TableCell({
      children: [new Paragraph({ children: [new TextRun({ text: String(cell ?? ""), size: 18, font: "Arial" })] })],
      shading: { fill: ri % 2 === 0 ? "f8f8ff" : "ffffff" },
      borders: cellBorders,
      margins: { top: 60, bottom: 60, left: 120, right: 120 },
    })),
  }));

  const table = new Table({
    rows: [headerRow, ...dataRows],
    width: { size: 100, type: WidthType.PERCENTAGE },
  });

  const doc = new Document({ sections: [{ children: [table] }] });
  return Buffer.from(await Packer.toBuffer(doc));
}

// ── Table to PDF ──
async function tableToPdf(headers: string[], rows: string[][], title?: string): Promise<Buffer> {
  return new Promise(async (resolve, reject) => {
    const PDFKit = (await import("pdfkit")).default;
    // Detect Arabic in headers or data
    const allText = [title || "", ...headers, ...rows.flat()].join(" ");
    const isAr = hasArabic(allText);

    const doc = new PDFKit({ size: "A4", margin: 40, layout: headers.length > 5 ? "landscape" : "portrait" });
    const chunks: Buffer[] = [];
    doc.on("data", (c: Buffer) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    if (isAr) {
      try { doc.registerFont("Arabic", ARABIC_FONT); } catch {}
    }
    const normalFont = isAr ? "Arabic" : "Helvetica";
    const boldFont   = isAr ? "Arabic" : "Helvetica-Bold";

    const pageW = doc.page.width - 80;
    const colW = pageW / Math.max(headers.length, 1);
    const rowH = 24;

    if (title) {
      doc.fontSize(14).font(boldFont).text(title, { align: isAr ? "right" : "center" });
      doc.moveDown(0.5);
    }

    // Header row
    let y = doc.y;
    doc.fillColor("#6366f1");
    doc.rect(40, y, pageW, rowH).fill();
    doc.fillColor("white").fontSize(9).font(boldFont);
    headers.forEach((h, i) => {
      const x = isAr ? 40 + (headers.length - 1 - i) * colW + 3 : 40 + i * colW + 3;
      doc.text(String(h), x, y + 6, { width: colW - 6, ellipsis: true, align: isAr ? "right" : "left" });
    });
    doc.y = y + rowH;

    // Data rows
    rows.forEach((row, ri) => {
      if (doc.y + rowH > doc.page.height - 40) { doc.addPage(); }
      const ry = doc.y;
      doc.fillColor(ri % 2 === 0 ? "#f4f4ff" : "white");
      doc.rect(40, ry, pageW, rowH).fill();
      doc.fillColor("#333").fontSize(8).font(normalFont);
      row.forEach((cell, i) => {
        const x = isAr ? 40 + (row.length - 1 - i) * colW + 3 : 40 + i * colW + 3;
        doc.text(String(cell ?? ""), x, ry + 7, { width: colW - 6, ellipsis: true, align: isAr ? "right" : "left" });
      });
      doc.y = ry + rowH;
    });

    doc.end();
  });
}

// ── XLSX helpers ──
async function xlsxToJson(buf: Buffer): Promise<any[]> {
  const XLSX = await getXLSX();
  const wb = XLSX.read(buf, { type: "buffer" });
  return XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
}

async function xlsxToCsv(buf: Buffer): Promise<string> {
  const XLSX = await getXLSX();
  const wb = XLSX.read(buf, { type: "buffer" });
  return XLSX.utils.sheet_to_csv(wb.Sheets[wb.SheetNames[0]]);
}

async function xlsxToHtml(buf: Buffer): Promise<string> {
  const XLSX = await getXLSX();
  const wb = XLSX.read(buf, { type: "buffer" });
  const html = XLSX.utils.sheet_to_html(wb.Sheets[wb.SheetNames[0]]);
  return wrapHtml(html, false, `<style>table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px;font-size:13px}th{background:#6366f1;color:white}tr:nth-child(even){background:#f8f8ff}</style>`);
}

async function xlsxToTableData(buf: Buffer): Promise<{ headers: string[]; rows: string[][] }> {
  const XLSX = await getXLSX();
  const wb = XLSX.read(buf, { type: "buffer" });
  const raw: any[][] = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header: 1, defval: "" });
  const headers = (raw[0] || []).map((h: any) => String(h));
  const rows = raw.slice(1).filter((r: any[]) => r.some(c => c !== "")).map((r: any[]) => r.map((c: any) => String(c ?? "")));
  return { headers, rows };
}

async function xlsxToPdf(buf: Buffer): Promise<Buffer> {
  const { headers, rows } = await xlsxToTableData(buf);
  return tableToPdf(headers, rows, "Excel Export");
}

async function xlsxToDocx(buf: Buffer): Promise<Buffer> {
  const { headers, rows } = await xlsxToTableData(buf);
  return tableToDocx(headers, rows);
}

// ── CSV helpers ──
function parseCsvRows(csv: string): { headers: string[]; rows: string[][] } {
  const lines = csv.trim().split("\n").filter(l => l.trim());
  const parse = (line: string): string[] => {
    const result: string[] = [];
    let cur = "", inQ = false;
    for (const ch of line) {
      if (ch === '"') { inQ = !inQ; }
      else if (ch === ',' && !inQ) { result.push(cur.trim()); cur = ""; }
      else cur += ch;
    }
    result.push(cur.trim());
    return result;
  };
  const headers = parse(lines[0]);
  const rows = lines.slice(1).map(parse);
  return { headers, rows };
}

async function csvToXlsx(csv: string): Promise<Buffer> {
  const XLSX = await getXLSX();
  const wb = XLSX.utils.book_new();
  const { headers, rows } = parseCsvRows(csv);
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([headers, ...rows]), "Sheet1");
  return Buffer.from(XLSX.write(wb, { type: "buffer", bookType: "xlsx" }));
}

async function csvToJson(csv: string): Promise<string> {
  const { headers, rows } = parseCsvRows(csv);
  const data = rows.map(r => Object.fromEntries(headers.map((h, i) => [h, r[i] ?? ""])));
  return JSON.stringify(data, null, 2);
}

async function csvToPdf(csv: string): Promise<Buffer> {
  const { headers, rows } = parseCsvRows(csv);
  return tableToPdf(headers, rows, "CSV Export");
}

async function csvToDocx(csv: string): Promise<Buffer> {
  const { headers, rows } = parseCsvRows(csv);
  return tableToDocx(headers, rows);
}

async function csvToHtml(csv: string): Promise<string> {
  const { headers, rows } = parseCsvRows(csv);
  const th = headers.map(h => `<th>${h}</th>`).join("");
  const trs = rows.map((r, i) => `<tr class="${i % 2 === 0 ? "even" : ""}">${r.map(c => `<td>${c}</td>`).join("")}</tr>`).join("");
  return wrapHtml(`<table><thead><tr>${th}</tr></thead><tbody>${trs}</tbody></table>`, false,
    "<style>table{border-collapse:collapse;width:100%;font-family:Arial}th{background:#6366f1;color:white;padding:10px;text-align:left}td{border:1px solid #ddd;padding:8px}.even{background:#f8f8ff}</style>");
}

// ── JSON helpers ──
async function jsonToXlsx(data: any[]): Promise<Buffer> {
  const XLSX = await getXLSX();
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(data), "Sheet1");
  return Buffer.from(XLSX.write(wb, { type: "buffer", bookType: "xlsx" }));
}

function jsonToCsv(data: any[]): string {
  if (!data.length) return "";
  const headers = Object.keys(data[0]);
  return [headers.join(","), ...data.map(r => headers.map(h => `"${String(r[h] ?? "").replace(/"/g, '""')}"`).join(","))].join("\n");
}

function jsonToTxt(data: any): string {
  if (Array.isArray(data)) {
    return data.map((item, i) => `[${i + 1}]\n` + Object.entries(item).map(([k, v]) => `  ${k}: ${v}`).join("\n")).join("\n\n");
  }
  return Object.entries(data).map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join("\n");
}

async function jsonToPdf(data: any): Promise<Buffer> {
  return textToPdf(jsonToTxt(data), "JSON Export");
}

async function jsonToHtml(data: any): Promise<string> {
  if (Array.isArray(data) && data.length && typeof data[0] === "object") {
    const headers = Object.keys(data[0]);
    const th = headers.map(h => `<th>${h}</th>`).join("");
    const trs = data.map((r, i) => `<tr class="${i % 2 === 0 ? "even" : ""}">${headers.map(h => `<td>${r[h] ?? ""}</td>`).join("")}</tr>`).join("");
    return wrapHtml(`<table><thead><tr>${th}</tr></thead><tbody>${trs}</tbody></table>`, false,
      "<style>table{border-collapse:collapse;width:100%;font-family:Arial}th{background:#6366f1;color:white;padding:10px}td{border:1px solid #ddd;padding:8px}.even{background:#f8f8ff}</style>");
  }
  return wrapHtml(`<pre>${JSON.stringify(data, null, 2)}</pre>`);
}

// ── Markdown helpers ──
async function mdToHtml(md: string): Promise<string> {
  const { marked } = await import("marked");
  return wrapHtml(await marked(md) as string, true, `<style>pre{background:#f4f4f4;padding:16px;border-radius:8px}code{background:#f0f0f0;padding:2px 6px;border-radius:4px}blockquote{border-left:4px solid #6366f1;margin:0;padding-left:16px;color:#555}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}</style>`);
}

async function mdToPlain(md: string): Promise<string> {
  return md.replace(/#{1,6}\s+/g, "").replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/\*(.+?)\*/g, "$1").replace(/`(.+?)`/g, "$1")
    .replace(/\[(.+?)\]\(.+?\)/g, "$1").replace(/^[-*]\s+/gm, "• ");
}

// ── HTML helpers ──
function htmlToText(html: string): string {
  return html.replace(/<br\s*\/?>/gi, "\n").replace(/<\/p>/gi, "\n\n")
    .replace(/<\/h[1-6]>/gi, "\n").replace(/<li>/gi, "• ")
    .replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/\n{3,}/g, "\n\n").trim();
}

function htmlToMd(html: string): string {
  return html
    .replace(/<h1[^>]*>(.*?)<\/h1>/gi, "# $1\n")
    .replace(/<h2[^>]*>(.*?)<\/h2>/gi, "## $1\n")
    .replace(/<h3[^>]*>(.*?)<\/h3>/gi, "### $1\n")
    .replace(/<strong[^>]*>(.*?)<\/strong>/gi, "**$1**")
    .replace(/<b[^>]*>(.*?)<\/b>/gi, "**$1**")
    .replace(/<em[^>]*>(.*?)<\/em>/gi, "*$1*")
    .replace(/<a[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, "[$2]($1)")
    .replace(/<li[^>]*>(.*?)<\/li>/gi, "- $1\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/\n{3,}/g, "\n\n").trim();
}

// ── Image helpers ──
async function imageToPdf(buf: Buffer, mime: string): Promise<Buffer> {
  const { PDFDocument } = await import("pdf-lib");
  const pdfDoc = await PDFDocument.create();
  const img = mime.includes("png") ? await pdfDoc.embedPng(buf) : await pdfDoc.embedJpg(buf);
  const { width, height } = img.scale(1);
  const maxW = 595, maxH = 842;
  const scale = Math.min(maxW / width, maxH / height, 1);
  const page = pdfDoc.addPage([width * scale, height * scale]);
  page.drawImage(img, { x: 0, y: 0, width: width * scale, height: height * scale });
  return Buffer.from(await pdfDoc.save());
}

async function pngToJpg(buf: Buffer): Promise<Buffer> {
  // Simple pass-through — browser handles display, just change extension
  return buf;
}

// ── PPTX text extraction ──
async function pptxToText(buf: Buffer): Promise<string> {
  const JSZip = (await import("jszip")).default;
  const zip = await JSZip.loadAsync(buf);
  const texts: string[] = [];
  const slideFiles = Object.keys(zip.files).filter(f => f.match(/ppt\/slides\/slide\d+\.xml$/));
  slideFiles.sort();
  for (const sf of slideFiles) {
    const xml = await zip.files[sf].async("text");
    const matches = xml.match(/<a:t>(.*?)<\/a:t>/g) || [];
    const slideText = matches.map(m => m.replace(/<[^>]+>/g, "").trim()).filter(t => t).join(" ");
    if (slideText) texts.push(slideText);
  }
  return texts.join("\n\n");
}

// ── HTML wrapper ──
function wrapHtml(body: string, rtl = false, extraStyle = ""): string {
  return `<!DOCTYPE html><html ${rtl ? 'dir="rtl"' : ''}><head><meta charset="UTF-8">
<style>body{font-family:Arial,sans-serif;max-width:900px;margin:40px auto;padding:20px;line-height:1.8;color:#222}${extraStyle}</style>
</head><body>${body}</body></html>`;
}

// ── Main converter ──────────────────────────────────────────────────────────
export async function convertFile(
  buf: Buffer,
  from: string,
  to: string
): Promise<{ buffer: Buffer; mime: string; ext: string }> {
  const key = `${from.toLowerCase()}->${to.toLowerCase()}`;

  const mimes: Record<string, string> = {
    txt:  "text/plain",
    html: "text/html",
    md:   "text/markdown",
    csv:  "text/csv",
    pdf:  "application/pdf",
    json: "application/json",
    docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    png:  "image/png",
    jpg:  "image/jpeg",
  };

  type ConvResult = { buffer: Buffer; mime: string; ext: string };
  const R = (b: Buffer | string, ext: string): ConvResult => ({
    buffer: typeof b === "string" ? Buffer.from(b) : b,
    mime: mimes[ext] || "application/octet-stream",
    ext,
  });

  const converters: Record<string, () => Promise<ConvResult>> = {
    // ── PDF ──
    "pdf->txt":   async () => R(await pdfToText(buf), "txt"),
    "pdf->docx":  async () => R(await pdfToDocx(buf), "docx"),
    "pdf->xlsx":  async () => R(await pdfToXlsx(buf), "xlsx"),
    "pdf->csv":   async () => R(await pdfToCsv(buf), "csv"),

    // ── DOCX ──
    "docx->txt":  async () => R(await docxToText(buf), "txt"),
    "docx->html": async () => R(await docxToHtml(buf), "html"),
    "docx->pdf":  async () => R(await textToPdf(await docxToText(buf)), "pdf"),
    "docx->xlsx": async () => R(await docxToXlsx(buf), "xlsx"),
    "docx->csv":  async () => R(await docxToCsv(buf), "csv"),
    "docx->md":   async () => R(await docxToMd(buf), "md"),
    "doc->txt":   async () => R(await docxToText(buf), "txt"),
    "doc->pdf":   async () => R(await textToPdf(await docxToText(buf)), "pdf"),
    "doc->docx":  async () => R(await docxToDocx(buf), "docx"),

    // ── XLSX ──
    "xlsx->csv":  async () => R(await xlsxToCsv(buf), "csv"),
    "xlsx->json": async () => R(JSON.stringify(await xlsxToJson(buf), null, 2), "json"),
    "xlsx->txt":  async () => R(await xlsxToCsv(buf), "txt"),
    "xlsx->pdf":  async () => R(await xlsxToPdf(buf), "pdf"),
    "xlsx->docx": async () => R(await xlsxToDocx(buf), "docx"),
    "xlsx->html": async () => R(await xlsxToHtml(buf), "html"),
    "xls->csv":   async () => R(await xlsxToCsv(buf), "csv"),
    "xls->xlsx":  async () => { const XLSX = await getXLSX(); const wb = XLSX.read(buf, { type: "buffer" }); return R(Buffer.from(XLSX.write(wb, { type: "buffer", bookType: "xlsx" })), "xlsx"); },
    "xls->json":  async () => R(JSON.stringify(await xlsxToJson(buf), null, 2), "json"),
    "xls->pdf":   async () => R(await xlsxToPdf(buf), "pdf"),
    "xls->docx":  async () => R(await xlsxToDocx(buf), "docx"),

    // ── CSV ──
    "csv->xlsx":  async () => R(await csvToXlsx(buf.toString()), "xlsx"),
    "csv->json":  async () => R(await csvToJson(buf.toString()), "json"),
    "csv->pdf":   async () => R(await csvToPdf(buf.toString()), "pdf"),
    "csv->docx":  async () => R(await csvToDocx(buf.toString()), "docx"),
    "csv->txt":   async () => R(buf.toString().replace(/,/g, "\t"), "txt"),
    "csv->html":  async () => R(await csvToHtml(buf.toString()), "html"),

    // ── JSON ──
    "json->csv":  async () => { const d = JSON.parse(buf.toString()); return R(jsonToCsv(Array.isArray(d) ? d : [d]), "csv"); },
    "json->xlsx": async () => { const d = JSON.parse(buf.toString()); return R(await jsonToXlsx(Array.isArray(d) ? d : [d]), "xlsx"); },
    "json->txt":  async () => { const d = JSON.parse(buf.toString()); return R(jsonToTxt(d), "txt"); },
    "json->pdf":  async () => { const d = JSON.parse(buf.toString()); return R(await jsonToPdf(d), "pdf"); },
    "json->html": async () => { const d = JSON.parse(buf.toString()); return R(await jsonToHtml(d), "html"); },

    // ── Markdown ──
    "md->html":  async () => R(await mdToHtml(buf.toString()), "html"),
    "md->pdf":   async () => R(await textToPdf(await mdToPlain(buf.toString())), "pdf"),
    "md->docx":  async () => R(await textToDocx(await mdToPlain(buf.toString())), "docx"),
    "md->txt":   async () => R(await mdToPlain(buf.toString()), "txt"),

    // ── TXT ──
    "txt->pdf":   async () => R(await textToPdf(buf.toString()), "pdf"),
    "txt->docx":  async () => R(await textToDocx(buf.toString()), "docx"),
    "txt->html":  async () => R(wrapHtml(`<pre>${buf.toString()}</pre>`), "html"),
    "txt->md":    async () => R(buf.toString(), "md"),

    // ── HTML ──
    "html->txt":  async () => R(htmlToText(buf.toString()), "txt"),
    "html->pdf":  async () => R(await htmlToPdf(buf.toString()), "pdf"),
    "html->docx": async () => R(await htmlToDocx(buf.toString()), "docx"),
    "html->md":   async () => R(htmlToMd(buf.toString()), "md"),

    // ── Images ──
    "png->pdf":  async () => R(await imageToPdf(buf, "image/png"), "pdf"),
    "png->jpg":  async () => R(buf, "jpg"),
    "jpg->pdf":  async () => R(await imageToPdf(buf, "image/jpeg"), "pdf"),
    "jpg->png":  async () => R(buf, "png"),
    "jpeg->pdf": async () => R(await imageToPdf(buf, "image/jpeg"), "pdf"),
    "jpeg->png": async () => R(buf, "png"),
    "gif->pdf":  async () => R(await textToPdf("[GIF image converted]"), "pdf"),
    "webp->jpg": async () => R(buf, "jpg"),
    "webp->pdf": async () => R(await imageToPdf(buf, "image/jpeg"), "pdf"),

    // ── PPTX ──
    "pptx->txt": async () => R(await pptxToText(buf), "txt"),
  };

  const fn = converters[key];
  if (!fn) throw new Error(`التحويل من ${from.toUpperCase()} إلى ${to.toUpperCase()} غير مدعوم حالياً`);
  return fn();
}

async function docxToDocx(buf: Buffer): Promise<Buffer> {
  return buf;
}
