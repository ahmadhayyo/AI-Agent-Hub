/**
 * Mermaid Diagram Component
 * Renders architectural and flow diagrams using Mermaid.js
 */

import React, { useEffect, useRef, useState } from "react";
import { AlertCircle, Download, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface MermaidDiagramProps {
  diagram: string;
  title?: string;
  onError?: (error: string) => void;
}

declare global {
  interface Window {
    mermaid?: any;
  }
}

export const MermaidDiagram: React.FC<MermaidDiagramProps> = ({
  diagram,
  title = "Architecture Diagram",
  onError,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Load Mermaid library
  useEffect(() => {
    const script = document.createElement("script");
    script.src = "https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js";
    script.async = true;
    script.onload = () => {
      if (window.mermaid) {
        window.mermaid.initialize({ startOnLoad: true, theme: "default" });
        renderDiagram();
      }
    };
    script.onerror = () => {
      const errorMsg = "Failed to load Mermaid library";
      setError(errorMsg);
      onError?.(errorMsg);
      setIsLoading(false);
    };
    document.head.appendChild(script);

    return () => {
      if (document.head.contains(script)) {
        document.head.removeChild(script);
      }
    };
  }, [onError]);

  // Render diagram
  const renderDiagram = async () => {
    if (!containerRef.current || !window.mermaid) return;

    try {
      setIsLoading(true);
      setError(null);

      containerRef.current.innerHTML = "";
      const div = document.createElement("div");
      div.className = "mermaid";
      div.textContent = diagram;
      containerRef.current.appendChild(div);

      // Re-render mermaid
      await window.mermaid.contentLoaded();
      setIsLoading(false);
    } catch (err: any) {
      const errorMsg = err.message || "Failed to render diagram";
      setError(errorMsg);
      onError?.(errorMsg);
      setIsLoading(false);
    }
  };

  // Re-render when diagram changes
  useEffect(() => {
    if (window.mermaid) {
      renderDiagram();
    }
  }, [diagram]);

  const handleDownloadSVG = () => {
    const svg = containerRef.current?.querySelector("svg");
    if (!svg) {
      toast.error("No diagram to download");
      return;
    }

    const svgData = new XMLSerializer().serializeToString(svg);
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    const img = new Image();

    img.onload = () => {
      canvas.width = img.width;
      canvas.height = img.height;
      ctx?.drawImage(img, 0, 0);
      const link = document.createElement("a");
      link.href = canvas.toDataURL("image/png");
      link.download = "diagram.png";
      link.click();
      toast.success("Diagram downloaded");
    };

    img.src = "data:image/svg+xml;base64," + btoa(svgData);
  };

  const handleCopyDiagram = () => {
    navigator.clipboard.writeText(diagram);
    toast.success("Diagram code copied");
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
            onClick={handleCopyDiagram}
            title="Copy diagram code"
          >
            <Copy className="w-4 h-4" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleDownloadSVG}
            title="Download as PNG"
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
            <p className="font-semibold text-destructive text-sm">Diagram Error</p>
            <p className="text-destructive/80 text-sm mt-1">{error}</p>
          </div>
        </div>
      )}

      {/* Diagram Container */}
      <div className="flex-1 overflow-auto p-4 flex items-center justify-center bg-white">
        {isLoading && (
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-2"></div>
            <p className="text-sm text-muted-foreground">Rendering diagram...</p>
          </div>
        )}
        <div
          ref={containerRef}
          className="w-full h-full flex items-center justify-center"
          style={{ display: isLoading ? "none" : "flex" }}
        />
      </div>

      {/* Footer Info */}
      <div className="px-4 py-2 border-t border-border bg-muted/30 text-xs text-muted-foreground">
        <p>📊 Mermaid diagram • Supports flowcharts, sequences, class diagrams, and more</p>
      </div>
    </div>
  );
};

export default MermaidDiagram;
