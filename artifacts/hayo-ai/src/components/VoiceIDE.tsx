/**
 * Voice IDE Component
 * Microphone input for voice commands to modify code
 */

import React, { useRef, useState } from "react";
import { Mic, MicOff, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface VoiceIDEProps {
  onTranscript: (text: string) => void;
  isProcessing?: boolean;
}

export const VoiceIDE: React.FC<VoiceIDEProps> = ({ onTranscript, isProcessing = false }) => {
  const [isListening, setIsListening] = useState(false);
  const [transcript, setTranscript] = useState("");
  const recognitionRef = useRef<any>(null);

  // Initialize Web Speech API
  const initializeRecognition = () => {
    const SpeechRecognition = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
    
    if (!SpeechRecognition) {
      toast.error("Speech Recognition not supported in your browser");
      return null;
    }

    const recognition = new SpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = true;
    recognition.lang = "en-US";

    recognition.onstart = () => {
      setIsListening(true);
      setTranscript("");
    };

    recognition.onresult = (event: any) => {
      let interim = "";
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const transcriptSegment = event.results[i][0].transcript;
        if (event.results[i].isFinal) {
          interim += transcriptSegment + " ";
        } else {
          interim += transcriptSegment;
        }
      }
      setTranscript(interim);
    };

    recognition.onerror = (event: any) => {
      toast.error(`Speech recognition error: ${event.error}`);
      setIsListening(false);
    };

    recognition.onend = () => {
      setIsListening(false);
      if (transcript.trim()) {
        onTranscript(transcript.trim());
      }
    };

    return recognition;
  };

  const handleStartListening = () => {
    if (!recognitionRef.current) {
      recognitionRef.current = initializeRecognition();
    }

    if (recognitionRef.current) {
      recognitionRef.current.start();
    }
  };

  const handleStopListening = () => {
    if (recognitionRef.current) {
      recognitionRef.current.stop();
    }
    setIsListening(false);
  };

  return (
    <div className="flex items-center gap-2">
      <Button
        size="sm"
        variant={isListening ? "destructive" : "default"}
        onClick={isListening ? handleStopListening : handleStartListening}
        disabled={isProcessing}
        className="gap-2"
        title="Voice command"
      >
        {isProcessing ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : isListening ? (
          <>
            <MicOff className="w-4 h-4" />
            Stop
          </>
        ) : (
          <>
            <Mic className="w-4 h-4" />
            Voice
          </>
        )}
      </Button>

      {isListening && (
        <div className="flex items-center gap-2 px-3 py-1 bg-primary/10 rounded-md">
          <div className="flex gap-1">
            <div className="w-1 h-3 bg-primary rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
            <div className="w-1 h-3 bg-primary rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
            <div className="w-1 h-3 bg-primary rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
          </div>
          <span className="text-xs text-primary font-medium">Listening...</span>
        </div>
      )}

      {transcript && (
        <div className="text-xs text-muted-foreground max-w-xs truncate">
          "{transcript}"
        </div>
      )}
    </div>
  );
};

export default VoiceIDE;
