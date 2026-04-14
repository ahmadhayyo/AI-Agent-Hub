/**
 * File Converter - محول الصيغ
 * تحويل بين Excel/CSV/PDF/Word/TXT
 */

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { Link } from "wouter";
import { Upload, Download, ArrowRight, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import ExcelHandler from "@/components/ExcelHandler";
import WordHandler from "@/components/WordHandler";
import PDFHandler from "@/components/PDFHandler";

export default function FileConverter() {
  const { t } = useTranslation();
  const { isAuthenticated } = useAuth();
  const [activeTab, setActiveTab] = useState<"excel" | "word" | "pdf">("excel");
  const [isConverting, setIsConverting] = useState(false);

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>يجب تسجيل الدخول</CardTitle>
            <CardDescription>قم بتسجيل الدخول لاستخدام محول الصيغ</CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild className="w-full">
              <a href={getLoginUrl()}>تسجيل الدخول</a>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background p-4">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Link href="/agent" className="text-muted-foreground hover:text-primary">
                ← العودة للوكيل
              </Link>
            </div>
            <h1 className="text-3xl font-bold">محول الصيغ</h1>
            <p className="text-muted-foreground mt-2">
              حول بين Excel و Word و PDF و CSV و النصوص
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 border-b border-border">
          <button
            onClick={() => setActiveTab("excel")}
            className={`px-4 py-2 font-medium border-b-2 transition-colors ${
              activeTab === "excel"
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            📊 Excel
          </button>
          <button
            onClick={() => setActiveTab("word")}
            className={`px-4 py-2 font-medium border-b-2 transition-colors ${
              activeTab === "word"
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            📄 Word
          </button>
          <button
            onClick={() => setActiveTab("pdf")}
            className={`px-4 py-2 font-medium border-b-2 transition-colors ${
              activeTab === "pdf"
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            📕 PDF
          </button>
        </div>

        {/* Content */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Main Handler */}
          <div>
            {activeTab === "excel" && <ExcelHandler />}
            {activeTab === "word" && <WordHandler />}
            {activeTab === "pdf" && <PDFHandler />}
          </div>

          {/* Conversion Guide */}
          <div className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">تحويلات متاحة</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {activeTab === "excel" && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-sm">
                      <span className="font-medium">Excel</span>
                      <ArrowRight className="w-4 h-4" />
                      <span className="text-muted-foreground">CSV</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <span className="font-medium">Excel</span>
                      <ArrowRight className="w-4 h-4" />
                      <span className="text-muted-foreground">PDF</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <span className="font-medium">CSV</span>
                      <ArrowRight className="w-4 h-4" />
                      <span className="text-muted-foreground">Excel</span>
                    </div>
                  </div>
                )}

                {activeTab === "word" && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-sm">
                      <span className="font-medium">Word</span>
                      <ArrowRight className="w-4 h-4" />
                      <span className="text-muted-foreground">PDF</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <span className="font-medium">Word</span>
                      <ArrowRight className="w-4 h-4" />
                      <span className="text-muted-foreground">النصوص</span>
                    </div>
                  </div>
                )}

                {activeTab === "pdf" && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-sm">
                      <span className="font-medium">PDF</span>
                      <ArrowRight className="w-4 h-4" />
                      <span className="text-green-600 font-medium">نص .txt ✓</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <span className="font-medium">PDF</span>
                      <ArrowRight className="w-4 h-4" />
                      <span className="text-green-600 font-medium">Word .docx ✓</span>
                    </div>
                    <p className="text-xs text-muted-foreground pt-1">* يعمل مع ملفات PDF النصية فقط (لا يدعم PDF المسحوب ضوئياً)</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Tips */}
            <Card className="bg-blue-50 border-blue-200">
              <CardHeader>
                <CardTitle className="text-sm">💡 نصائح</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-blue-900 space-y-2">
                <p>✓ يمكنك تحرير البيانات قبل التحويل</p>
                <p>✓ جميع التحويلات تتم محلياً في متصفحك</p>
                <p>✓ لا يتم حفظ أي بيانات على الخادم</p>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
