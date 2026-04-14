/**
 * PDF Handler - تحويل ملفات PDF
 * PDF → نص | PDF → Word
 */
import { useState, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Upload, Download, Loader2, FileText, File } from "lucide-react";
import { toast } from "sonner";

type ConvertTarget = "text" | "word";

export default function PDFHandler() {
  const [file, setFile] = useState<File | null>(null);
  const [extractedText, setExtractedText] = useState<string>("");
  const [isLoading, setIsLoading] = useState(false);
  const [target, setTarget] = useState<ConvertTarget>("text");
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = (f: File) => {
    if (f.type !== "application/pdf") {
      toast.error("يرجى اختيار ملف PDF فقط");
      return;
    }
    setFile(f);
    setExtractedText("");
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  };

  const extractText = async (): Promise<string> => {
    if (!file) return "";
    const pdfjsLib = await import("pdfjs-dist");
    pdfjsLib.GlobalWorkerOptions.workerSrc = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.mjs`;

    const arrayBuffer = await file.arrayBuffer();
    const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
    let fullText = "";

    for (let i = 1; i <= pdf.numPages; i++) {
      const page = await pdf.getPage(i);
      const content = await page.getTextContent();
      const pageText = content.items
        .map((item: any) => item.str)
        .join(" ");
      fullText += `--- صفحة ${i} ---\n${pageText}\n\n`;
    }
    return fullText.trim();
  };

  const convertToText = async () => {
    if (!file) return;
    setIsLoading(true);
    try {
      const text = await extractText();
      setExtractedText(text);
      toast.success("تم استخراج النص بنجاح!");
    } catch (err) {
      toast.error("فشل في قراءة الملف. تأكد أنه PDF نصي وليس صورة.");
    } finally {
      setIsLoading(false);
    }
  };

  const downloadText = () => {
    const blob = new Blob([extractedText], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${file?.name.replace(".pdf", "")}_text.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const convertToWord = async () => {
    if (!file) return;
    setIsLoading(true);
    try {
      const text = await extractText();
      setExtractedText(text);

      const { Document, Packer, Paragraph, TextRun } = await import("docx");
      const lines = text.split("\n");
      const paragraphs = lines.map((line) =>
        new Paragraph({
          children: [new TextRun({ text: line, size: 24 })],
          spacing: { after: 120 },
        })
      );

      const doc = new Document({
        sections: [{ properties: {}, children: paragraphs }],
      });

      const buffer = await Packer.toBlob(doc);
      const url = URL.createObjectURL(buffer);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${file.name.replace(".pdf", "")}.docx`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("تم تحويل PDF إلى Word بنجاح!");
    } catch (err) {
      toast.error("فشل التحويل. تأكد أن الملف PDF نصي.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <FileText className="w-4 h-4 text-red-500" />
            محول PDF
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div
            onDrop={handleDrop}
            onDragOver={(e) => e.preventDefault()}
            onClick={() => inputRef.current?.click()}
            className="border-2 border-dashed border-border rounded-lg p-8 text-center cursor-pointer hover:border-primary/50 hover:bg-muted/30 transition-colors"
          >
            <input
              ref={inputRef}
              type="file"
              accept=".pdf"
              className="hidden"
              onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
            />
            <Upload className="w-8 h-8 mx-auto mb-2 text-muted-foreground" />
            {file ? (
              <div className="space-y-1">
                <p className="font-medium text-foreground">{file.name}</p>
                <p className="text-sm text-muted-foreground">
                  {(file.size / 1024).toFixed(1)} KB
                </p>
              </div>
            ) : (
              <div>
                <p className="text-sm font-medium">اسحب ملف PDF هنا أو انقر للتحديد</p>
                <p className="text-xs text-muted-foreground mt-1">يدعم فقط ملفات PDF النصية (لا يدعم الصور)</p>
              </div>
            )}
          </div>

          {file && (
            <div className="flex gap-2 flex-wrap">
              <Button
                onClick={convertToText}
                disabled={isLoading}
                variant="outline"
                className="flex-1"
              >
                {isLoading && target === "text" ? (
                  <Loader2 className="w-4 h-4 animate-spin mr-2" />
                ) : (
                  <FileText className="w-4 h-4 mr-2" />
                )}
                استخراج النص
              </Button>
              <Button
                onClick={convertToWord}
                disabled={isLoading}
                className="flex-1 bg-blue-600 hover:bg-blue-700"
              >
                {isLoading && target === "word" ? (
                  <Loader2 className="w-4 h-4 animate-spin mr-2" />
                ) : (
                  <File className="w-4 h-4 mr-2" />
                )}
                تحويل إلى Word
              </Button>
            </div>
          )}

          {extractedText && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium">النص المستخرج</p>
                <Button size="sm" variant="outline" onClick={downloadText}>
                  <Download className="w-3 h-3 mr-1" />
                  تحميل .txt
                </Button>
              </div>
              <div className="bg-muted rounded-md p-3 text-sm text-muted-foreground max-h-48 overflow-y-auto whitespace-pre-wrap font-mono text-xs">
                {extractedText.substring(0, 1000)}
                {extractedText.length > 1000 && (
                  <span className="text-primary"> ... ({extractedText.length} حرف)</span>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
