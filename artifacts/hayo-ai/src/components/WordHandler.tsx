/**
 * Word Handler - معالج ملفات Word
 * قراءة وتحرير وحفظ ملفات Word
 */

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Upload, Download, Loader2, Bold, Italic, Underline } from "lucide-react";
import { toast } from "sonner";

interface WordContent {
  paragraphs: {
    text: string;
    style: "normal" | "heading1" | "heading2" | "bold" | "italic";
  }[];
}

interface WordHandlerProps {
  onContentChange?: (content: WordContent) => void;
}

export default function WordHandler({ onContentChange }: WordHandlerProps) {
  const [wordContent, setWordContent] = useState<WordContent>({ paragraphs: [] });
  const [isLoading, setIsLoading] = useState(false);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsLoading(true);
    try {
      const mammoth = (await import("mammoth")).default;
      const arrayBuffer = await file.arrayBuffer();
      const result = await mammoth.extractRawText({ arrayBuffer });

      const paragraphs = result.value.split("\n").map((text) => ({
        text: text.trim(),
        style: "normal" as const,
      }));

      setWordContent({ paragraphs: paragraphs.filter((p) => p.text) });
      onContentChange?.({ paragraphs: paragraphs.filter((p) => p.text) });
      toast.success(`تم تحميل ${file.name}`);
    } catch (error: any) {
      toast.error("فشل تحميل ملف Word");
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownloadWord = async () => {
    try {
      const { Document, Packer, Paragraph, TextRun, HeadingLevel } = await import("docx");

      const docParagraphs = wordContent.paragraphs.map((para) => {
        const styleMap: Record<string, any> = {
          heading1: { heading: HeadingLevel.HEADING_1 },
          heading2: { heading: HeadingLevel.HEADING_2 },
          bold: {},
          italic: {},
          normal: {},
        };

        const style = styleMap[para.style] || {};
        return new Paragraph({
          text: para.text,
          ...style,
        });
      });

      const doc = new Document({
        sections: [
          {
            children: docParagraphs,
          },
        ],
      });

      const blob = await Packer.toBlob(doc);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "export.docx";
      link.click();
      URL.revokeObjectURL(url);

      toast.success("تم تحميل ملف Word");
    } catch (error) {
      toast.error("فشل تحميل الملف");
    }
  };

  const handleConvertToPDF = async () => {
    try {
      const { PDFDocument, rgb, degrees } = await import("pdf-lib");

      const pdfDoc = await PDFDocument.create();
      const page = pdfDoc.addPage([612, 792]);
      const { height } = page.getSize();

      let y = height - 50;
      const fontSize = 12;
      const lineHeight = 20;

      wordContent.paragraphs.forEach((para) => {
        if (y < 50) {
          const newPage = pdfDoc.addPage([612, 792]);
          y = newPage.getHeight() - 50;
        }

        page.drawText(para.text, {
          x: 50,
          y,
          size: fontSize,
          color: rgb(0, 0, 0),
        });

        y -= lineHeight;
      });

      const pdfBytes = await pdfDoc.save();
      const blob = new Blob([pdfBytes.buffer as ArrayBuffer], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "export.pdf";
      link.click();
      URL.revokeObjectURL(url);

      toast.success("تم تحويل إلى PDF");
    } catch (error) {
      toast.error("فشل التحويل");
    }
  };

  const handleAddParagraph = () => {
    setWordContent({
      paragraphs: [...wordContent.paragraphs, { text: "", style: "normal" }],
    });
  };

  const handleUpdateParagraph = (index: number, text: string) => {
    const updated = [...wordContent.paragraphs];
    updated[index].text = text;
    setWordContent({ paragraphs: updated });
    onContentChange?.({ paragraphs: updated });
  };

  const handleDeleteParagraph = (index: number) => {
    const updated = wordContent.paragraphs.filter((_, i) => i !== index);
    setWordContent({ paragraphs: updated });
    onContentChange?.({ paragraphs: updated });
  };

  const handleChangeStyle = (index: number, style: string) => {
    const updated = [...wordContent.paragraphs];
    updated[index].style = style as any;
    setWordContent({ paragraphs: updated });
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">معالج Word</CardTitle>
          <CardDescription>رفع وتحرير وتحويل ملفات Word</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Upload */}
          <div className="flex gap-2">
            <label className="flex-1">
              <input
                type="file"
                accept=".docx,.doc"
                onChange={handleFileUpload}
                className="hidden"
              />
              <Button asChild className="w-full cursor-pointer gap-2">
                <span>
                  <Upload className="w-4 h-4" />
                  رفع ملف Word
                </span>
              </Button>
            </label>
          </div>

          {/* Content Editor */}
          {wordContent.paragraphs.length > 0 && (
            <div className="space-y-3 max-h-96 overflow-y-auto border border-input rounded-lg p-3">
              {wordContent.paragraphs.map((para, idx) => (
                <div key={idx} className="flex gap-2 items-start">
                  <select
                    value={para.style}
                    onChange={(e) => handleChangeStyle(idx, e.target.value)}
                    className="px-2 py-1 text-xs border border-input rounded bg-background"
                  >
                    <option value="normal">عادي</option>
                    <option value="heading1">عنوان 1</option>
                    <option value="heading2">عنوان 2</option>
                    <option value="bold">غامق</option>
                    <option value="italic">مائل</option>
                  </select>
                  <textarea
                    value={para.text}
                    onChange={(e) => handleUpdateParagraph(idx, e.target.value)}
                    className="flex-1 px-2 py-1 text-sm border border-input rounded bg-background resize-none"
                    rows={2}
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => handleDeleteParagraph(idx)}
                    className="h-8"
                  >
                    ✕
                  </Button>
                </div>
              ))}
            </div>
          )}

          {/* Actions */}
          {wordContent.paragraphs.length > 0 && (
            <div className="flex gap-2">
              <Button onClick={handleAddParagraph} variant="outline" className="gap-2 flex-1">
                + إضافة فقرة
              </Button>
              <Button onClick={handleDownloadWord} className="gap-2 flex-1">
                <Download className="w-4 h-4" />
                تحميل Word
              </Button>
              <Button onClick={handleConvertToPDF} variant="outline" className="gap-2 flex-1">
                تحويل إلى PDF
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
