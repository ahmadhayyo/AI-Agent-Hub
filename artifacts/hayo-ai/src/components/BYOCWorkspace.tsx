/**
 * BYOC (Bring Your Own Code) Workspace
 * Users paste existing code, agent analyzes, fixes, and executes it
 */

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Upload, Play, Zap, CheckCircle2, AlertCircle, Copy, Trash2 } from "lucide-react";
import { toast } from "sonner";
import Editor from "@monaco-editor/react";

interface BYOCProps {
  onAnalyze?: (code: string, language: string) => void;
  isAnalyzing?: boolean;
  analysisResult?: string;
}

export const BYOCWorkspace: React.FC<BYOCProps> = ({
  onAnalyze,
  isAnalyzing = false,
  analysisResult,
}) => {
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("javascript");
  const [showEditor, setShowEditor] = useState(false);

  const handleAnalyzeAndFix = () => {
    if (!code.trim()) {
      toast.error("Please paste some code first");
      return;
    }
    onAnalyze?.(code, language);
  };

  const handleClearCode = () => {
    setCode("");
    setShowEditor(false);
    toast.success("Code cleared");
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(code);
    toast.success("Code copied to clipboard");
  };

  const languages = [
    { value: "javascript", label: "JavaScript" },
    { value: "python", label: "Python" },
    { value: "typescript", label: "TypeScript" },
    { value: "java", label: "Java" },
    { value: "cpp", label: "C++" },
    { value: "csharp", label: "C#" },
    { value: "php", label: "PHP" },
    { value: "go", label: "Go" },
    { value: "rust", label: "Rust" },
    { value: "sql", label: "SQL" },
    { value: "html", label: "HTML" },
    { value: "css", label: "CSS" },
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Bring Your Own Code (BYOC)</h3>
          <p className="text-sm text-muted-foreground">
            Paste existing code for AI analysis, fixes, and execution
          </p>
        </div>
        <Button
          onClick={() => setShowEditor(!showEditor)}
          variant={showEditor ? "default" : "outline"}
          className="gap-2"
        >
          <Upload className="w-4 h-4" />
          {showEditor ? "Hide Editor" : "Paste Code"}
        </Button>
      </div>

      {/* Code Editor */}
      {showEditor && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Code Input</CardTitle>
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="px-3 py-1 text-sm border border-input rounded-md bg-background"
              >
                {languages.map((lang) => (
                  <option key={lang.value} value={lang.value}>
                    {lang.label}
                  </option>
                ))}
              </select>
            </div>
            <CardDescription>
              Paste your code below. The AI will analyze, fix bugs, optimize, and execute it.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Monaco Editor */}
            <div className="border border-input rounded-lg overflow-hidden bg-background">
              <Editor
                height="400px"
                language={language}
                value={code}
                onChange={(value) => setCode(value || "")}
                theme="vs-dark"
                options={{
                  minimap: { enabled: false },
                  fontSize: 13,
                  lineNumbers: "on",
                  scrollBeyondLastLine: false,
                  automaticLayout: true,
                }}
              />
            </div>

            {/* Code Stats */}
            {code && (
              <div className="flex items-center justify-between text-sm text-muted-foreground">
                <span>{code.split("\n").length} lines • {code.length} characters</span>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={handleCopyCode}
                    className="gap-1"
                  >
                    <Copy className="w-3 h-3" />
                    Copy
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={handleClearCode}
                    className="gap-1 text-destructive hover:text-destructive"
                  >
                    <Trash2 className="w-3 h-3" />
                    Clear
                  </Button>
                </div>
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex gap-2">
              <Button
                onClick={handleAnalyzeAndFix}
                disabled={!code.trim() || isAnalyzing}
                className="flex-1 gap-2"
              >
                {isAnalyzing ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    Analyze & Fix
                  </>
                )}
              </Button>
              <Button
                variant="outline"
                onClick={() => setShowEditor(false)}
                disabled={isAnalyzing}
              >
                Close
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Analysis Result */}
      {analysisResult && (
        <Card className="border-green-200 bg-green-50">
          <CardHeader>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-green-600" />
              <CardTitle className="text-base text-green-900">Analysis Complete</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="bg-white p-4 rounded-lg border border-green-200 max-h-96 overflow-auto">
              <pre className="text-sm font-mono text-foreground whitespace-pre-wrap break-words">
                {analysisResult}
              </pre>
            </div>
            <div className="flex gap-2 mt-4">
              <Button className="flex-1 gap-2">
                <Play className="w-4 h-4" />
                Execute Fixed Code
              </Button>
              <Button variant="outline" onClick={() => setShowEditor(false)}>
                Close
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty State */}
      {!showEditor && !analysisResult && (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Upload className="w-12 h-12 text-muted-foreground mb-4 opacity-50" />
            <h4 className="font-semibold mb-2">No code pasted yet</h4>
            <p className="text-sm text-muted-foreground mb-4">
              Click "Paste Code" above to import your existing code for analysis and fixes
            </p>
            <Button onClick={() => setShowEditor(true)} className="gap-2">
              <Upload className="w-4 h-4" />
              Start Importing Code
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default BYOCWorkspace;
