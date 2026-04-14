/**
 * Excel Handler - معالج ملفات Excel
 * قراءة وتحرير وحفظ ملفات Excel
 */

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Upload, Download, Plus, Trash2, Loader2 } from "lucide-react";
import { toast } from "sonner";

interface ExcelData {
  sheets: {
    name: string;
    data: string[][];
  }[];
}

interface ExcelHandlerProps {
  onDataChange?: (data: ExcelData) => void;
}

export default function ExcelHandler({ onDataChange }: ExcelHandlerProps) {
  const [excelData, setExcelData] = useState<ExcelData>({ sheets: [] });
  const [activeSheet, setActiveSheet] = useState(0);
  const [isLoading, setIsLoading] = useState(false);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsLoading(true);
    try {
      // Dynamic import of xlsx library
      const XLSX = (await import("xlsx")).default;
      const arrayBuffer = await file.arrayBuffer();
      const workbook = XLSX.read(arrayBuffer, { type: "array" });

      const sheets = workbook.SheetNames.map((sheetName) => {
        const worksheet = workbook.Sheets[sheetName];
        const data = XLSX.utils.sheet_to_json(worksheet, { header: 1 }) as string[][];
        return { name: sheetName, data };
      });

      setExcelData({ sheets });
      setActiveSheet(0);
      onDataChange?.({ sheets });
      toast.success(`تم تحميل ${file.name}`);
    } catch (error: any) {
      toast.error("فشل تحميل ملف Excel");
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownloadExcel = () => {
    try {
      // Dynamic import of xlsx library
      import("xlsx").then(({ default: XLSX }) => {
        const workbook = XLSX.utils.book_new();

        excelData.sheets.forEach((sheet) => {
          const worksheet = XLSX.utils.aoa_to_sheet(sheet.data);
          XLSX.utils.book_append_sheet(workbook, worksheet, sheet.name);
        });

        XLSX.writeFile(workbook, "export.xlsx");
        toast.success("تم تحميل ملف Excel");
      });
    } catch (error) {
      toast.error("فشل تحميل الملف");
    }
  };

  const handleConvertToCSV = () => {
    try {
      if (excelData.sheets.length === 0) {
        toast.error("لا توجد بيانات");
        return;
      }

      const sheet = excelData.sheets[activeSheet];
      const csv = sheet.data.map((row) => row.map((cell) => `"${cell}"`).join(",")).join("\n");

      const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `${sheet.name}.csv`;
      link.click();

      toast.success("تم تحويل إلى CSV");
    } catch (error) {
      toast.error("فشل التحويل");
    }
  };

  const handleCellChange = (rowIndex: number, colIndex: number, value: string) => {
    const newData = [...excelData.sheets];
    if (!newData[activeSheet].data[rowIndex]) {
      newData[activeSheet].data[rowIndex] = [];
    }
    newData[activeSheet].data[rowIndex][colIndex] = value;
    setExcelData({ sheets: newData });
    onDataChange?.({ sheets: newData });
  };

  const handleAddRow = () => {
    const newData = [...excelData.sheets];
    const sheet = newData[activeSheet];
    if (sheet.data.length === 0) {
      sheet.data.push([]);
    }
    sheet.data.push(new Array(sheet.data[0]?.length || 5).fill(""));
    setExcelData({ sheets: newData });
  };

  const handleDeleteRow = (rowIndex: number) => {
    const newData = [...excelData.sheets];
    newData[activeSheet].data.splice(rowIndex, 1);
    setExcelData({ sheets: newData });
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">معالج Excel</CardTitle>
          <CardDescription>رفع وتحرير وتحويل ملفات Excel</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Upload */}
          <div className="flex gap-2">
            <label className="flex-1">
              <input
                type="file"
                accept=".xlsx,.xls,.csv"
                onChange={handleFileUpload}
                className="hidden"
              />
              <Button asChild className="w-full cursor-pointer gap-2">
                <span>
                  <Upload className="w-4 h-4" />
                  رفع ملف Excel
                </span>
              </Button>
            </label>
          </div>

          {/* Sheets Tabs */}
          {excelData.sheets.length > 0 && (
            <div className="flex gap-2 overflow-x-auto pb-2">
              {excelData.sheets.map((sheet, idx) => (
                <button
                  key={idx}
                  onClick={() => setActiveSheet(idx)}
                  className={`px-3 py-1 text-sm rounded-lg whitespace-nowrap transition-colors ${
                    activeSheet === idx
                      ? "bg-primary text-primary-foreground"
                      : "bg-secondary hover:bg-secondary/80"
                  }`}
                >
                  {sheet.name}
                </button>
              ))}
            </div>
          )}

          {/* Data Table */}
          {excelData.sheets.length > 0 && (
            <div className="border border-input rounded-lg overflow-auto max-h-96">
              <table className="w-full text-sm">
                <tbody>
                  {excelData.sheets[activeSheet].data.map((row, rowIdx) => (
                    <tr key={rowIdx} className="border-b border-input hover:bg-secondary/50">
                      <td className="px-2 py-1 text-xs text-muted-foreground bg-secondary/30 w-8 text-center">
                        {rowIdx + 1}
                      </td>
                      {row.map((cell, colIdx) => (
                        <td key={colIdx} className="px-2 py-1 border-r border-input">
                          <input
                            type="text"
                            value={cell}
                            onChange={(e) => handleCellChange(rowIdx, colIdx, e.target.value)}
                            className="w-full bg-transparent outline-none"
                            placeholder="..."
                          />
                        </td>
                      ))}
                      <td className="px-2 py-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleDeleteRow(rowIdx)}
                          className="h-6 gap-1"
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Actions */}
          {excelData.sheets.length > 0 && (
            <div className="flex gap-2">
              <Button onClick={handleAddRow} variant="outline" className="gap-2 flex-1">
                <Plus className="w-4 h-4" />
                إضافة صف
              </Button>
              <Button onClick={handleDownloadExcel} className="gap-2 flex-1">
                <Download className="w-4 h-4" />
                تحميل Excel
              </Button>
              <Button onClick={handleConvertToCSV} variant="outline" className="gap-2 flex-1">
                تحويل إلى CSV
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
