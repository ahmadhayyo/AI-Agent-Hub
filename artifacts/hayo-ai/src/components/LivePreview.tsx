/**
 * Live Preview Component
 * Real-time rendering of HTML/CSS/JS code in a sandboxed iframe
 */

import React, { useEffect, useRef, useState } from "react";
import { AlertCircle, RefreshCw, Copy, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface LivePreviewProps {
  code: string;
  title?: string;
  height?: string;
  onError?: (error: string) => void;
}

export const LivePreview: React.FC<LivePreviewProps> = ({
  code,
  title = "Live Preview",
  height = "600px",
  onError,
}) => {
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Update iframe content when code changes
  useEffect(() => {
    if (!iframeRef.current) return;

    try {
      setIsLoading(true);
      setError(null);

      // Wrap code with error handling
      const wrappedCode = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
          </style>
        </head>
        <body>
          <script>
            window.addEventListener('error', (event) => {
              console.error('Preview Error:', event.error);
              document.body.innerHTML = '<div style="color: red; padding: 20px;"><strong>Error:</strong> ' + event.error.message + '</div>';
            });
          </script>
          ${code}
        </body>
        </html>
      `;

      // Set iframe content
      const iframeDoc = iframeRef.current.contentDocument || iframeRef.current.contentWindow?.document;
      if (iframeDoc) {
        iframeDoc.open();
        iframeDoc.write(wrappedCode);
        iframeDoc.close();
      }

      setIsLoading(false);
    } catch (err: any) {
      const errorMsg = err.message || "Failed to render preview";
      setError(errorMsg);
      onError?.(errorMsg);
      setIsLoading(false);
    }
  }, [code, onError]);

  const handleRefresh = () => {
    setIsLoading(true);
    setTimeout(() => setIsLoading(false), 500);
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(code);
    toast.success("Code copied to clipboard");
  };

  const handleDownloadHTML = () => {
    const element = document.createElement("a");
    element.setAttribute("href", "data:text/html;charset=utf-8," + encodeURIComponent(code));
    element.setAttribute("download", "preview.html");
    element.style.display = "none";
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    toast.success("HTML file downloaded");
  };

  return (
    <div className="flex flex-col h-full bg-background rounded-lg border border-border">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-border bg-muted/50">
        <h3 className="font-semibold text-foreground">{title}</h3>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="ghost"
            onClick={handleRefresh}
            disabled={isLoading}
            title="Refresh preview"
          >
            <RefreshCw className="w-4 h-4" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleCopyCode}
            title="Copy code"
          >
            <Copy className="w-4 h-4" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleDownloadHTML}
            title="Download HTML"
          >
            <Download className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="flex items-start gap-3 p-4 bg-destructive/10 border-b border-destructive/20">
          <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="font-semibold text-destructive text-sm">Preview Error</p>
            <p className="text-destructive/80 text-sm mt-1">{error}</p>
          </div>
        </div>
      )}

      {/* Preview Container */}
      <div className="flex-1 overflow-hidden bg-white">
        {isLoading && (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-2"></div>
              <p className="text-sm text-muted-foreground">Loading preview...</p>
            </div>
          </div>
        )}
        <iframe
          ref={iframeRef}
          className="w-full h-full border-none"
          sandbox="allow-scripts allow-forms allow-popups allow-modals"
          title="Live Preview"
          style={{ display: isLoading ? "none" : "block" }}
        />
      </div>

      {/* Footer Info */}
      <div className="px-4 py-2 border-t border-border bg-muted/30 text-xs text-muted-foreground">
        <p>
          🔒 Sandboxed environment • Scripts enabled • External resources allowed
        </p>
      </div>
    </div>
  );
};

export default LivePreview;
