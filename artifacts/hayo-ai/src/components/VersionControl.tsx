/**
 * Version Control Component
 * Time-travel snapshots for code history
 */

import React, { useState } from "react";
import { Save, RotateCcw, Trash2, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

export interface CodeSnapshot {
  id: string;
  timestamp: Date;
  code: string;
  description: string;
  language: string;
}

interface VersionControlProps {
  currentCode: string;
  language?: string;
  onRestore: (code: string) => void;
  onSnapshotCreated?: (snapshot: CodeSnapshot) => void;
}

export const VersionControl: React.FC<VersionControlProps> = ({
  currentCode,
  language = "javascript",
  onRestore,
  onSnapshotCreated,
}) => {
  const [snapshots, setSnapshots] = useState<CodeSnapshot[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [description, setDescription] = useState("");

  const handleSaveSnapshot = () => {
    const snapshot: CodeSnapshot = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      code: currentCode,
      description: description || `Snapshot at ${new Date().toLocaleTimeString()}`,
      language,
    };

    setSnapshots([snapshot, ...snapshots]);
    setDescription("");
    onSnapshotCreated?.(snapshot);
    toast.success("Snapshot saved");
  };

  const handleRestoreSnapshot = (snapshot: CodeSnapshot) => {
    onRestore(snapshot.code);
    toast.success(`Restored to: ${snapshot.description}`);
    setShowHistory(false);
  };

  const handleDeleteSnapshot = (id: string) => {
    setSnapshots(snapshots.filter((s) => s.id !== id));
    toast.success("Snapshot deleted");
  };

  const handleClearHistory = () => {
    if (confirm("Are you sure you want to delete all snapshots?")) {
      setSnapshots([]);
      toast.success("History cleared");
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Save Snapshot Section */}
      <div className="flex gap-2">
        <input
          type="text"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Snapshot description (optional)"
          className="flex-1 px-3 py-2 rounded-md border border-input bg-background text-sm"
          onKeyPress={(e) => e.key === "Enter" && handleSaveSnapshot()}
        />
        <Button
          size="sm"
          onClick={handleSaveSnapshot}
          className="gap-2"
          title="Save current code as snapshot"
        >
          <Save className="w-4 h-4" />
          Save
        </Button>
      </div>

      {/* History Toggle */}
      {snapshots.length > 0 && (
        <Button
          size="sm"
          variant="outline"
          onClick={() => setShowHistory(!showHistory)}
          className="gap-2 w-full"
        >
          <Clock className="w-4 h-4" />
          {snapshots.length} Snapshot{snapshots.length !== 1 ? "s" : ""} • Timeline
        </Button>
      )}

      {/* Snapshots History */}
      {showHistory && snapshots.length > 0 && (
        <div className="border border-border rounded-lg overflow-hidden">
          {/* Timeline */}
          <div className="flex flex-col">
            {snapshots.map((snapshot, index) => (
              <div
                key={snapshot.id}
                className="flex items-start gap-3 p-3 border-b border-border last:border-b-0 hover:bg-muted/50 transition-colors"
              >
                {/* Timeline Dot */}
                <div className="flex flex-col items-center pt-1">
                  <div className="w-3 h-3 rounded-full bg-primary" />
                  {index < snapshots.length - 1 && (
                    <div className="w-0.5 h-12 bg-border mt-1" />
                  )}
                </div>

                {/* Snapshot Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1">
                      <p className="font-medium text-sm text-foreground">
                        {snapshot.description}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {snapshot.timestamp.toLocaleString()}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {snapshot.code.length} characters • {snapshot.language}
                      </p>
                    </div>

                    {/* Actions */}
                    <div className="flex gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleRestoreSnapshot(snapshot)}
                        title="Restore this snapshot"
                      >
                        <RotateCcw className="w-3 h-3" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleDeleteSnapshot(snapshot.id)}
                        title="Delete snapshot"
                      >
                        <Trash2 className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Clear History Button */}
          {snapshots.length > 0 && (
            <div className="p-3 border-t border-border bg-muted/30">
              <Button
                size="sm"
                variant="outline"
                onClick={handleClearHistory}
                className="w-full gap-2 text-destructive hover:text-destructive"
              >
                <Trash2 className="w-4 h-4" />
                Clear All Snapshots
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {snapshots.length === 0 && showHistory && (
        <div className="text-center py-8 text-muted-foreground">
          <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No snapshots yet. Save your first snapshot above.</p>
        </div>
      )}
    </div>
  );
};

export default VersionControl;
