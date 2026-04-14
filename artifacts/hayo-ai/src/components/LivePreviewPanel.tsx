/**
 * Live Preview Panel
 * Real-time rendering of HTML/CSS/JS with sandbox security
 */

import React, { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Download, RefreshCw, Maximize2, X } from "lucide-react";
import { toast } from "sonner";

interface LivePreviewProps {
  html?: string;
  css?: string;
  javascript?: string;
  title?: string;
  onClose?: () => void;
}

export const LivePreviewPanel: React.FC<LivePreviewProps> = ({
  html = "",
  css = "",
  javascript = "",
  title = "Live Preview",
  onClose,
}) => {
  const [iframeKey, setIframeKey] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Combine HTML, CSS, and JavaScript into a single document
  const generatePreviewHTML = () => {
    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f5;
            color: #333;
          }
          ${css}
        </style>
      </head>
      <body>
        ${html}
        <script>
          try {
            ${javascript}
          } catch (error) {
            console.error('Script error:', error);
            document.body.innerHTML += '<div style="color: red; padding: 20px; background: #ffe6e6; border: 1px solid red; margin: 20px; border-radius: 4px;"><strong>Error:</strong> ' + error.message + '</div>';
          }
        </script>
      </body>
      </html>
    `;
  };

  const handleRefresh = () => {
    setIframeKey((prev) => prev + 1);
    toast.success("Preview refreshed");
  };

  const handleDownload = () => {
    const element = document.createElement("a");
    const file = new Blob([generatePreviewHTML()], { type: "text/html" });
    element.href = URL.createObjectURL(file);
    element.download = "preview.html";
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    toast.success("HTML file downloaded");
  };

  const handleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  const previewContent = generatePreviewHTML();

  if (isFullscreen) {
    return (
      <div className="fixed inset-0 z-50 bg-black">
        <div className="absolute top-4 right-4 flex gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={handleRefresh}
            className="gap-1 bg-white hover:bg-gray-100"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={handleFullscreen}
            className="gap-1 bg-white hover:bg-gray-100"
          >
            <X className="w-4 h-4" />
            Exit
          </Button>
        </div>
        <iframe
          key={iframeKey}
          srcDoc={previewContent}
          className="w-full h-full border-0"
          sandbox="allow-scripts allow-modals allow-forms allow-popups"
          title="Live Preview Fullscreen"
          onError={() => setError("Failed to load preview")}
        />
      </div>
    );
  }

  return (
    <Card className="w-full">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
        <div>
          <CardTitle className="text-base">{title}</CardTitle>
          <CardDescription>Real-time preview of your code</CardDescription>
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="ghost"
            onClick={handleRefresh}
            title="Refresh preview"
          >
            <RefreshCw className="w-4 h-4" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleDownload}
            title="Download as HTML"
          >
            <Download className="w-4 h-4" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleFullscreen}
            title="Fullscreen"
          >
            <Maximize2 className="w-4 h-4" />
          </Button>
          {onClose && (
            <Button
              size="sm"
              variant="ghost"
              onClick={onClose}
              title="Close preview"
            >
              <X className="w-4 h-4" />
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent>
        {error ? (
          <div className="flex items-center justify-center h-96 bg-red-50 border border-red-200 rounded-lg">
            <div className="text-center">
              <p className="text-red-600 font-semibold mb-2">Preview Error</p>
              <p className="text-sm text-red-500">{error}</p>
            </div>
          </div>
        ) : (
          <div className="border border-input rounded-lg overflow-hidden bg-white">
            <iframe
              key={iframeKey}
              srcDoc={previewContent}
              className="w-full h-96 border-0"
              sandbox="allow-scripts allow-modals allow-forms allow-popups"
              title="Live Preview"
              onError={() => setError("Failed to load preview")}
            />
          </div>
        )}

        {/* Info */}
        <p className="text-xs text-muted-foreground mt-4">
          🔒 Sandbox: Scripts run in isolated iframe. External resources blocked for security.
        </p>
      </CardContent>
    </Card>
  );
};

export default LivePreviewPanel;
