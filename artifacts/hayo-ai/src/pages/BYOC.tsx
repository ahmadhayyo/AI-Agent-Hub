/**
 * BYOC - Bring Your Own Code (Professional IDE)
 * User pastes code → AI fixes → Execute (run in browser) → Download ZIP
 */

import { useState, useRef, useCallback, useMemo, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { trpc } from "@/lib/trpc";
import { Link } from "wouter";
import Editor, { type OnMount } from "@monaco-editor/react";
import type * as Monaco from "monaco-editor";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import {
  Copy,
  Upload,
  FolderArchive,
  MessageSquare,
  FileCode,
  Loader2,
  Code2,
  Bot,
  ChevronRight,
  ChevronDown,
  Wrench,
  Plus,
  FolderPlus,
  FilePlus,
  Eye,
  EyeOff,
  Folder,
  File,
  X,
  Home,
  PanelLeftClose,
  PanelLeft,
  Maximize2,
  Minimize2,
  Play,
  Square,
  Download,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

// ─── Types ───────────────────────────────────────────────────────────
interface FileNode {
  id: string;
  name: string;
  type: "file" | "folder";
  content?: string;
  language?: string;
  children?: FileNode[];
  isOpen?: boolean;
}

interface OpenTab {
  fileId: string;
  name: string;
  language: string;
  modified: boolean;
}

interface ConsoleEntry {
  text: string;
  type: "info" | "success" | "error" | "system" | "output";
}

// ─── Templates ───────────────────────────────────────────────────────
const TEMPLATES: { id: string; name: string; nameAr: string; icon: string; description: string; files: FileNode[] }[] = [
  {
    id: "html-css-js",
    name: "HTML/CSS/JS",
    nameAr: "صفحة ويب",
    icon: "🌐",
    description: "موقع ويب بسيط مع HTML, CSS, JavaScript",
    files: [
      { id: "t1-index", name: "index.html", type: "file", language: "html", content: '<!DOCTYPE html>\n<html lang="ar" dir="rtl">\n<head>\n  <meta charset="UTF-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n  <title>مشروعي</title>\n  <link rel="stylesheet" href="style.css">\n</head>\n<body>\n  <div class="container">\n    <h1>مرحباً بالعالم!</h1>\n    <p>هذا مشروع HTML/CSS/JS جديد</p>\n    <button id="btn">اضغط هنا</button>\n    <div id="output"></div>\n  </div>\n  <script src="script.js"></script>\n</body>\n</html>' },
      { id: "t1-style", name: "style.css", type: "file", language: "css", content: '* {\n  margin: 0;\n  padding: 0;\n  box-sizing: border-box;\n}\n\nbody {\n  font-family: "Segoe UI", Tahoma, sans-serif;\n  background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);\n  color: #fff;\n  min-height: 100vh;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n}\n\n.container {\n  text-align: center;\n  padding: 2rem;\n}\n\nh1 {\n  font-size: 2.5rem;\n  margin-bottom: 1rem;\n  background: linear-gradient(to right, #667eea, #764ba2);\n  -webkit-background-clip: text;\n  -webkit-text-fill-color: transparent;\n}\n\nbutton {\n  padding: 12px 32px;\n  font-size: 1rem;\n  border: none;\n  border-radius: 8px;\n  background: linear-gradient(135deg, #667eea, #764ba2);\n  color: #fff;\n  cursor: pointer;\n  margin-top: 1rem;\n  transition: transform 0.2s;\n}\n\nbutton:hover {\n  transform: scale(1.05);\n}\n\n#output {\n  margin-top: 1.5rem;\n  font-size: 1.2rem;\n  color: #a5b4fc;\n}' },
      { id: "t1-script", name: "script.js", type: "file", language: "javascript", content: "// Main Script\nlet clickCount = 0;\n\nconst btn = document.getElementById('btn');\nconst output = document.getElementById('output');\n\nbtn.addEventListener('click', () => {\n  clickCount++;\n  output.textContent = `عدد النقرات: ${clickCount}`;\n  btn.style.transform = 'scale(0.95)';\n  setTimeout(() => btn.style.transform = 'scale(1)', 150);\n});\n\nconsole.log('Script loaded successfully!');" },
    ],
  },
  {
    id: "python-script",
    name: "Python Script",
    nameAr: "سكربت بايثون",
    icon: "🐍",
    description: "سكربت Python مع أمثلة متقدمة",
    files: [
      { id: "t2-main", name: "main.py", type: "file", language: "python", content: '#!/usr/bin/env python3\n"""HAYO AI - Python Project Template"""\n\nimport json\nfrom datetime import datetime\n\ndef greet(name: str) -> str:\n    return f"مرحباً {name}! الوقت الآن: {datetime.now().strftime(\'%H:%M:%S\')}"\n\ndef analyze_data(data: list[dict]) -> dict:\n    if not data:\n        return {"error": "No data provided"}\n    return {\n        "total_records": len(data),\n        "timestamp": datetime.now().isoformat(),\n        "status": "success"\n    }\n\nif __name__ == "__main__":\n    print(greet("Developer"))\n    sample = [\n        {"id": 1, "name": "Item A", "value": 100},\n        {"id": 2, "name": "Item B", "value": 200},\n    ]\n    result = analyze_data(sample)\n    print(json.dumps(result, indent=2, ensure_ascii=False))' },
      { id: "t2-req", name: "requirements.txt", type: "file", language: "plaintext", content: "# Python Dependencies\nrequests>=2.31.0\npandas>=2.0.0\nnumpy>=1.24.0" },
      { id: "t2-readme", name: "README.md", type: "file", language: "markdown", content: "# Python Project\n\n## Setup\n```bash\npip install -r requirements.txt\npython main.py\n```" },
    ],
  },
  {
    id: "node-express",
    name: "Node.js API",
    nameAr: "واجهة API",
    icon: "🟢",
    description: "خادم Express.js مع REST API",
    files: [
      { id: "t3-server", name: "server.js", type: "file", language: "javascript", content: "const express = require('express');\nconst cors = require('cors');\n\nconst app = express();\nconst PORT = process.env.PORT || 3000;\n\napp.use(cors());\napp.use(express.json());\n\nlet items = [\n  { id: 1, name: 'Item 1', status: 'active' },\n  { id: 2, name: 'Item 2', status: 'active' },\n];\n\napp.get('/api/items', (req, res) => {\n  res.json({ success: true, data: items, total: items.length });\n});\n\napp.post('/api/items', (req, res) => {\n  const { name } = req.body;\n  if (!name) return res.status(400).json({ error: 'Name required' });\n  const newItem = { id: items.length + 1, name, status: 'active' };\n  items.push(newItem);\n  res.status(201).json({ success: true, data: newItem });\n});\n\napp.listen(PORT, () => console.log(`Server on port ${PORT}`));" },
      { id: "t3-pkg", name: "package.json", type: "file", language: "json", content: '{\n  "name": "hayo-api",\n  "version": "1.0.0",\n  "scripts": { "start": "node server.js" },\n  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }\n}' },
    ],
  },
  {
    id: "react-app",
    name: "React App",
    nameAr: "تطبيق React",
    icon: "⚛️",
    description: "تطبيق React مع مكونات جاهزة",
    files: [
      { id: "t4-app", name: "App.jsx", type: "file", language: "javascript", content: "import React, { useState } from 'react';\n\nfunction App() {\n  const [count, setCount] = useState(0);\n  const [items, setItems] = useState([]);\n  const [input, setInput] = useState('');\n\n  const addItem = () => {\n    if (!input.trim()) return;\n    setItems([...items, { id: Date.now(), text: input, done: false }]);\n    setInput('');\n  };\n\n  return (\n    <div style={{ maxWidth: 600, margin: '2rem auto', padding: '2rem', fontFamily: 'sans-serif' }}>\n      <h1>My React App ⚛️</h1>\n      <div style={{ display: 'flex', gap: '1rem', margin: '1rem 0' }}>\n        <button onClick={() => setCount(c => c - 1)}>-</button>\n        <span style={{ fontSize: '1.5rem' }}>{count}</span>\n        <button onClick={() => setCount(c => c + 1)}>+</button>\n      </div>\n      <div>\n        <input value={input} onChange={e => setInput(e.target.value)}\n          onKeyDown={e => e.key === 'Enter' && addItem()} placeholder='Add item...'\n          style={{ padding: '8px', marginLeft: '8px', borderRadius: '4px', border: '1px solid #ccc' }} />\n        <button onClick={addItem} style={{ padding: '8px 16px' }}>Add</button>\n        <ul>{items.map(item => (\n          <li key={item.id} style={{ padding: '8px', cursor: 'pointer',\n            textDecoration: item.done ? 'line-through' : 'none' }}\n            onClick={() => setItems(items.map(i => i.id === item.id ? { ...i, done: !i.done } : i))}>\n            {item.text}\n          </li>\n        ))}</ul>\n      </div>\n    </div>\n  );\n}\n\nexport default App;" },
    ],
  },
  {
    id: "empty",
    name: "Empty Project",
    nameAr: "مشروع فارغ",
    icon: "📄",
    description: "ابدأ من الصفر",
    files: [
      { id: "t6-main", name: "main.js", type: "file", language: "javascript", content: "// ابدأ البرمجة هنا\nconsole.log('مرحباً من HAYO IDE!');\n\n// أضف كودك هنا...\n" },
    ],
  },
];

// ─── Helpers ─────────────────────────────────────────────────────────
function detectLanguage(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  const map: Record<string, string> = {
    js: "javascript", jsx: "javascript", ts: "typescript", tsx: "typescript",
    py: "python", html: "html", css: "css", json: "json", md: "markdown",
    sql: "sql", sh: "shell", yml: "yaml", yaml: "yaml", xml: "xml",
    java: "java", cpp: "cpp", c: "c", rb: "ruby", php: "php",
    go: "go", rs: "rust", txt: "plaintext",
  };
  return map[ext] || "plaintext";
}

let _idCounter = 0;
function generateId(): string {
  _idCounter++;
  return "f" + _idCounter + "-" + Math.random().toString(36).substring(2, 6);
}

function findFileById(nodes: FileNode[], id: string): FileNode | null {
  for (const node of nodes) {
    if (node.id === id) return node;
    if (node.children) {
      const found = findFileById(node.children, id);
      if (found) return found;
    }
  }
  return null;
}

function updateFileContent(nodes: FileNode[], id: string, content: string): FileNode[] {
  return nodes.map((node) => {
    if (node.id === id) return { ...node, content };
    if (node.children) return { ...node, children: updateFileContent(node.children, id, content) };
    return node;
  });
}

function addNodeToParent(nodes: FileNode[], parentId: string | null, newNode: FileNode): FileNode[] {
  if (!parentId) return [...nodes, newNode];
  return nodes.map((node) => {
    if (node.id === parentId && node.type === "folder") {
      return { ...node, children: [...(node.children || []), newNode], isOpen: true };
    }
    if (node.children) return { ...node, children: addNodeToParent(node.children, parentId, newNode) };
    return node;
  });
}

function deleteNodeById(nodes: FileNode[], id: string): FileNode[] {
  return nodes.filter((n) => n.id !== id).map((node) => {
    if (node.children) return { ...node, children: deleteNodeById(node.children, id) };
    return node;
  });
}

function flattenFiles(nodes: FileNode[], prefix = ""): { name: string; content: string; language?: string }[] {
  const result: { name: string; content: string; language?: string }[] = [];
  for (const node of nodes) {
    const path = prefix ? `${prefix}/${node.name}` : node.name;
    if (node.type === "file" && node.content !== undefined) {
      result.push({ name: path, content: node.content, language: node.language });
    }
    if (node.children) {
      result.push(...flattenFiles(node.children, path));
    }
  }
  return result;
}

// Build HTML preview from all project files (inline CSS + JS)
function buildProjectHtml(files: { name: string; content: string }[]): string {
  const htmlFile = files.find((f) => f.name.endsWith(".html") || f.name === "index.html");
  const cssFiles = files.filter((f) => f.name.endsWith(".css"));
  const jsFiles = files.filter((f) => f.name.endsWith(".js") && !f.name.includes("package"));

  if (htmlFile) {
    let html = htmlFile.content;
    // Inline CSS
    if (cssFiles.length > 0) {
      const cssBlock = cssFiles.map((f) => `<style>/* ${f.name} */\n${f.content}</style>`).join("\n");
      if (html.includes("</head>")) html = html.replace("</head>", `${cssBlock}\n</head>`);
      else html = `${cssBlock}\n${html}`;
      // Remove external CSS links since we inlined them
      html = html.replace(/<link[^>]*rel=["']stylesheet["'][^>]*>/gi, "");
    }
    // Inline JS
    if (jsFiles.length > 0) {
      const jsBlock = jsFiles.map((f) => `<script>/* ${f.name} */\n${f.content}<\/script>`).join("\n");
      if (html.includes("</body>")) html = html.replace("</body>", `${jsBlock}\n</body>`);
      else html += `\n${jsBlock}`;
      // Remove external JS script tags
      html = html.replace(/<script[^>]*src=["'][^"']*\.js["'][^>]*><\/script>/gi, "");
    }
    return html;
  }

  // JS-only: wrap in console-capturing HTML
  if (jsFiles.length > 0) {
    const jsCode = jsFiles.map((f) => f.content).join("\n\n");
    const cssCode = cssFiles.map((f) => f.content).join("\n");
    return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<style>
body { background: #0f0f1a; color: #e2e8f0; font-family: 'JetBrains Mono', monospace; padding: 16px; font-size: 13px; }
.log-entry { padding: 4px 0; border-bottom: 1px solid #1e293b; }
.log-info { color: #94a3b8; }
.log-error { color: #f87171; }
.log-warn { color: #fbbf24; }
.log-result { color: #4ade80; }
h3 { color: #818cf8; font-family: monospace; margin: 12px 0 6px; }
${cssCode}
</style>
</head>
<body>
<h3>🖥️ Console Output</h3>
<div id="console-output"></div>
<script>
const consoleDiv = document.getElementById('console-output');
const origLog = console.log;
const origErr = console.error;
const origWarn = console.warn;

function appendLog(text, cls) {
  const div = document.createElement('div');
  div.className = 'log-entry ' + cls;
  div.textContent = '> ' + (typeof text === 'object' ? JSON.stringify(text, null, 2) : String(text));
  consoleDiv.appendChild(div);
}

console.log = (...args) => { origLog(...args); args.forEach(a => appendLog(a, 'log-info')); };
console.error = (...args) => { origErr(...args); args.forEach(a => appendLog(a, 'log-error')); };
console.warn = (...args) => { origWarn(...args); args.forEach(a => appendLog(a, 'log-warn')); };

try {
${jsCode}
} catch(e) {
  appendLog('خطأ: ' + e.message, 'log-error');
}
<\/script>
</body>
</html>`;
  }

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>body{background:#0f0f1a;color:#64748b;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}</style></head><body><p>لا توجد ملفات HTML أو JavaScript للتشغيل</p></body></html>`;
}

// Detect project type
function detectProjectType(files: { name: string }[]): "web" | "node" | "python" | "other" {
  const names = files.map((f) => f.name.toLowerCase());
  if (names.some((n) => n.endsWith(".html"))) return "web";
  if (names.some((n) => n.endsWith(".js") || n.endsWith(".jsx") || n.endsWith(".ts") || n.endsWith(".tsx"))) {
    if (names.some((n) => n === "package.json" || n === "server.js")) return "node";
    return "web";
  }
  if (names.some((n) => n.endsWith(".py"))) return "python";
  return "other";
}

// ─── Component ───────────────────────────────────────────────────────
export default function BYOC() {
  const { isAuthenticated, loading: authLoading } = useAuth();
  const { t } = useTranslation();

  // State
  const [fileTree, setFileTree] = useState<FileNode[]>([]);
  const [openTabs, setOpenTabs] = useState<OpenTab[]>([]);
  const [activeTabId, setActiveTabId] = useState<string | null>(null);
  const [showTemplates, setShowTemplates] = useState(true);
  const [showPreview, setShowPreview] = useState(false);
  const [showSidebar, setShowSidebar] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isFixingAll, setIsFixingAll] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [consoleOutput, setConsoleOutput] = useState<ConsoleEntry[]>([
    { text: "[HAYO IDE] جاهز للاستخدام. ضع كودك أو اختر قالباً.", type: "system" },
    { text: "[HAYO IDE] اضغط ▶ تشغيل لتنفيذ مشروعك.", type: "info" },
  ]);
  const [newItemName, setNewItemName] = useState("");
  const [newItemType, setNewItemType] = useState<"file" | "folder" | null>(null);
  const [showRunModal, setShowRunModal] = useState(false);
  const [runHtml, setRunHtml] = useState("");
  const [projectType, setProjectType] = useState<"web" | "node" | "python" | "other">("web");
  const [showConsole, setShowConsole] = useState(true);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const editorRef = useRef<Monaco.editor.IStandaloneCodeEditor | null>(null);
  const consoleEndRef = useRef<HTMLDivElement>(null);
  const fixMutation = trpc.agent.fix.useMutation();

  const addLog = useCallback((text: string, type: ConsoleEntry["type"] = "info") => {
    setConsoleOutput((prev) => [...prev, { text, type }]);
  }, []);

  // Auto-scroll console
  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [consoleOutput]);

  const handleEditorMount: OnMount = useCallback((editor) => {
    editorRef.current = editor;
    editor.focus();
  }, []);

  const activeFile = useMemo(() => {
    if (!activeTabId) return null;
    return findFileById(fileTree, activeTabId);
  }, [activeTabId, fileTree]);

  // ─── Template Selection ──────────────────────────────────────────
  const handleSelectTemplate = useCallback((templateId: string) => {
    const template = TEMPLATES.find((t) => t.id === templateId);
    if (!template) return;
    const newFiles = template.files.map((f) => ({ ...f, id: generateId() }));
    setFileTree(newFiles);
    setShowTemplates(false);
    if (newFiles.length > 0 && newFiles[0].type === "file") {
      const first = newFiles[0];
      setOpenTabs([{ fileId: first.id, name: first.name, language: first.language || "plaintext", modified: false }]);
      setActiveTabId(first.id);
    }
    addLog(`[TEMPLATE] تم تحميل: ${template.nameAr} (${newFiles.length} ملف)`, "success");
    toast.success(`تم تحميل القالب: ${template.nameAr}`);
  }, [addLog]);

  // ─── File Operations ─────────────────────────────────────────────
  const openFile = useCallback((node: FileNode) => {
    if (node.type !== "file") return;
    setOpenTabs((prev) => {
      const existing = prev.find((t) => t.fileId === node.id);
      if (existing) return prev;
      return [...prev, { fileId: node.id, name: node.name, language: node.language || detectLanguage(node.name), modified: false }];
    });
    setActiveTabId(node.id);
  }, []);

  const closeTab = useCallback((fileId: string) => {
    setOpenTabs((prev) => {
      const filtered = prev.filter((t) => t.fileId !== fileId);
      if (activeTabId === fileId) {
        setActiveTabId(filtered.length > 0 ? filtered[filtered.length - 1].fileId : null);
      }
      return filtered;
    });
  }, [activeTabId]);

  const handleEditorChange = useCallback((value: string | undefined) => {
    if (value === undefined || !activeTabId) return;
    setFileTree((prev) => updateFileContent(prev, activeTabId, value));
    setOpenTabs((prev) => prev.map((t) => t.fileId === activeTabId ? { ...t, modified: true } : t));
  }, [activeTabId]);

  useEffect(() => {
    if (editorRef.current && activeFile) {
      const currentValue = editorRef.current.getValue();
      if (currentValue !== activeFile.content) {
        editorRef.current.setValue(activeFile.content || "");
      }
    }
  }, [activeTabId]);

  const handleCreateItem = useCallback(() => {
    if (!newItemName.trim() || !newItemType) return;
    const newNode: FileNode = {
      id: generateId(),
      name: newItemName.trim(),
      type: newItemType,
      ...(newItemType === "file" ? { content: "", language: detectLanguage(newItemName.trim()) } : { children: [], isOpen: true }),
    };
    setFileTree((prev) => addNodeToParent(prev, null, newNode));
    setNewItemName("");
    setNewItemType(null);
    if (newItemType === "file") openFile(newNode);
    toast.success(`تم إنشاء: ${newItemName.trim()}`);
  }, [newItemName, newItemType, openFile]);

  const handleDeleteNode = useCallback((id: string) => {
    setFileTree((prev) => deleteNodeById(prev, id));
    closeTab(id);
    toast.success("تم الحذف");
  }, [closeTab]);

  // ─── File Upload ─────────────────────────────────────────────────
  const handleFileUpload = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFiles = event.target.files;
    if (!uploadedFiles) return;
    Array.from(uploadedFiles).forEach((file) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        const newNode: FileNode = { id: generateId(), name: file.name, type: "file", content, language: detectLanguage(file.name) };
        setFileTree((prev) => [...prev, newNode]);
        openFile(newNode);
        addLog(`[UPLOAD] ${file.name} (${content.length} حرف)`, "success");
      };
      reader.readAsText(file);
    });
    toast.success(`تم رفع ${uploadedFiles.length} ملف`);
    if (showTemplates) setShowTemplates(false);
  }, [openFile, showTemplates, addLog]);

  // ─── AI Fix (current file) ────────────────────────────────────────
  const handleAiFix = useCallback(async () => {
    if (!activeFile || !activeFile.content || isProcessing) return;
    setIsProcessing(true);
    addLog(`[AI FIX] جاري تحليل ${activeFile.name}...`, "system");
    try {
      const result = await fixMutation.mutateAsync({ code: activeFile.content, fileName: activeFile.name, category: "general" });
      if (result.fixedCode) {
        setFileTree((prev) => updateFileContent(prev, activeFile.id, result.fixedCode));
        addLog(`[AI FIX] ✓ تم إصلاح ${activeFile.name}`, "success");
        result.fixes.forEach((f: string) => addLog(`  > ${f}`, "output"));
        toast.success(`AI Fix - ${activeFile.name}`);
      }
    } catch (error: any) {
      addLog(`[AI FIX] خطأ: ${error.message}`, "error");
      toast.error("فشل إصلاح الكود");
    }
    setIsProcessing(false);
  }, [activeFile, isProcessing, fixMutation, addLog]);

  // ─── AI Fix All Files ─────────────────────────────────────────────
  const handleAiFixAll = useCallback(async () => {
    const allFiles = flattenFiles(fileTree).filter((f) =>
      ["javascript", "typescript", "python", "html", "css", "java", "cpp", "go", "rust", "php"].includes(f.language || "")
    );
    if (allFiles.length === 0) { toast.error("لا توجد ملفات كود للإصلاح"); return; }
    if (isFixingAll || isProcessing) return;
    setIsFixingAll(true);
    addLog(`[AI FIX ALL] بدء إصلاح ${allFiles.length} ملف...`, "system");

    let fixedCount = 0;
    for (const file of allFiles) {
      addLog(`[AI FIX ALL] جاري إصلاح ${file.name}...`, "info");
      try {
        const result = await fixMutation.mutateAsync({ code: file.content, fileName: file.name, category: "general" });
        if (result.fixedCode && result.fixedCode !== file.content) {
          // Update the file in the tree
          setFileTree((prev) => {
            const findAndUpdate = (nodes: FileNode[]): FileNode[] =>
              nodes.map((n) => {
                if (n.type === "file" && (n.name === file.name || file.name.endsWith(n.name))) return { ...n, content: result.fixedCode };
                if (n.children) return { ...n, children: findAndUpdate(n.children) };
                return n;
              });
            return findAndUpdate(prev);
          });
          addLog(`  ✓ ${file.name} - ${result.fixes.length} إصلاح`, "success");
          fixedCount++;
        } else {
          addLog(`  ✓ ${file.name} - لا توجد إصلاحات مطلوبة`, "output");
        }
      } catch (error: any) {
        addLog(`  ✗ ${file.name} - خطأ: ${error.message}`, "error");
      }
    }

    addLog(`[AI FIX ALL] اكتمل! تم إصلاح ${fixedCount} من ${allFiles.length} ملف.`, "success");
    toast.success(`تم إصلاح ${fixedCount} ملف بواسطة AI`);
    setIsFixingAll(false);
  }, [fileTree, isFixingAll, isProcessing, fixMutation, addLog]);

  // ─── Run / Execute Project ────────────────────────────────────────
  const handleRunProject = useCallback(() => {
    const allFiles = flattenFiles(fileTree);
    if (allFiles.length === 0) { toast.error("لا توجد ملفات للتشغيل"); return; }

    const pType = detectProjectType(allFiles);
    setProjectType(pType);
    setIsRunning(true);

    addLog(`[RUN] بدء تنفيذ المشروع (${pType.toUpperCase()})...`, "system");

    if (pType === "web" || pType === "node") {
      // Build and show in-browser HTML
      const html = buildProjectHtml(allFiles);
      setRunHtml(html);
      setShowRunModal(true);
      addLog("[RUN] ✓ تم تشغيل المشروع في نافذة المعاينة", "success");
      toast.success("تم تشغيل المشروع! 🚀");
    } else if (pType === "python") {
      setRunHtml("");
      setShowRunModal(true);
      addLog("[RUN] مشاريع Python تحتاج إلى تشغيل محلي - راجع نافذة التشغيل", "info");
    } else {
      setRunHtml("");
      setShowRunModal(true);
      addLog("[RUN] هذا النوع من المشاريع يحتاج إلى تشغيل محلي", "info");
    }

    setIsRunning(false);
  }, [fileTree, addLog]);

  // ─── Download ZIP ────────────────────────────────────────────────
  const handleDownloadZip = useCallback(async () => {
    const allFiles = flattenFiles(fileTree);
    if (allFiles.length === 0) { toast.error("لا توجد ملفات"); return; }
    try {
      const JSZip = (await import("jszip")).default;
      const zip = new JSZip();
      allFiles.forEach((f) => zip.file(f.name, f.content));
      const blob = await zip.generateAsync({ type: "blob" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "hayo-project.zip";
      a.click();
      URL.revokeObjectURL(url);
      addLog(`[ZIP] تم تحميل ${allFiles.length} ملف`, "success");
      toast.success("تم تحميل المشروع كـ ZIP");
    } catch { toast.error("فشل التحميل"); }
  }, [fileTree, addLog]);

  const handleCopyAll = useCallback(() => {
    const allFiles = flattenFiles(fileTree);
    const allCode = allFiles.map((f) => `// === ${f.name} ===\n${f.content}`).join("\n\n");
    navigator.clipboard.writeText(allCode);
    toast.success("تم نسخ كل الكود");
  }, [fileTree]);

  const toggleFolder = useCallback((id: string) => {
    setFileTree((prev) => {
      const toggle = (nodes: FileNode[]): FileNode[] =>
        nodes.map((n) => {
          if (n.id === id) return { ...n, isOpen: !n.isOpen };
          if (n.children) return { ...n, children: toggle(n.children) };
          return n;
        });
      return toggle(prev);
    });
  }, []);

  // ─── Auth Check ──────────────────────────────────────────────────
  if (authLoading) {
    return <div className="h-screen bg-background flex items-center justify-center"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
  }

  if (!isAuthenticated) {
    return (
      <div className="h-screen bg-background flex items-center justify-center p-4">
        <div className="bg-card border border-border rounded-xl p-8 max-w-md w-full text-center space-y-4">
          <Code2 className="w-16 h-16 mx-auto text-primary opacity-60" />
          <h2 className="text-2xl font-bold">{t("byoc.title")} – BYOC</h2>
          <p className="text-muted-foreground">{t("common.loginDesc")}</p>
          <Button asChild className="w-full"><a href={getLoginUrl()}>{t("common.login")}</a></Button>
        </div>
      </div>
    );
  }

  // ─── Template Selection Screen ────────────────────────────────────
  if (showTemplates && fileTree.length === 0) {
    return (
      <div className="h-screen bg-background text-foreground flex flex-col">
        <header className="h-12 bg-card border-b border-border flex items-center justify-between px-4 shrink-0">
          <div className="flex items-center gap-3">
            <Link href="/" className="text-muted-foreground hover:text-primary transition-colors px-2 py-1 rounded hover:bg-primary/10"><Home className="w-4 h-4" /></Link>
            <div className="w-px h-5 bg-border" />
            <Code2 className="w-5 h-5 text-primary" />
            <span className="font-heading font-bold text-sm">HAYO IDE – BYOC</span>
            <span className="text-[9px] text-muted-foreground px-1.5 py-0.5 bg-secondary rounded">v3.0</span>
          </div>
          <div className="flex items-center gap-2">
            <input ref={fileInputRef} type="file" multiple onChange={handleFileUpload} className="hidden"
              accept=".js,.py,.ts,.java,.cpp,.cs,.php,.go,.rs,.sql,.html,.css,.txt,.json,.md,.jsx,.tsx,.yml,.yaml,.xml,.sh" />
            <LanguageSwitcher />
            <Button variant="outline" size="sm" className="text-xs gap-1 h-7" onClick={() => fileInputRef.current?.click()}>
              <Upload className="w-3 h-3" /> رفع ملفاتك
            </Button>
          </div>
        </header>
        <div className="flex-1 overflow-auto p-8">
          <div className="max-w-4xl mx-auto space-y-8">
            <div className="text-center space-y-3">
              <div className="inline-flex items-center gap-2 bg-primary/10 text-primary px-4 py-2 rounded-full text-sm font-medium mb-2">
                <Code2 className="w-4 h-4" /> BYOC – Bring Your Own Code
              </div>
              <h1 className="text-3xl font-heading font-bold">اختر نوع مشروعك</h1>
              <p className="text-muted-foreground max-w-xl mx-auto">
                اختر قالباً أو ارفع ملفاتك الخاصة، ثم يصلحها AI وتضغط ▶ تشغيل لتنفيذ المشروع وتحميله
              </p>
            </div>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {TEMPLATES.map((template) => (
                <button key={template.id} onClick={() => handleSelectTemplate(template.id)}
                  className="group text-right bg-card border border-border rounded-xl p-5 hover:border-primary/50 hover:shadow-lg hover:shadow-primary/5 transition-all duration-200">
                  <div className="text-3xl mb-3">{template.icon}</div>
                  <h3 className="font-heading font-bold text-base mb-1">{template.nameAr}</h3>
                  <p className="text-xs text-muted-foreground mb-2">{template.name}</p>
                  <p className="text-xs text-muted-foreground leading-relaxed">{template.description}</p>
                  <div className="mt-3 text-xs text-primary opacity-0 group-hover:opacity-100 transition-opacity">{template.files.length} ملف ← اضغط للبدء</div>
                </button>
              ))}
            </div>
            <div className="flex flex-col items-center gap-3">
              <Button variant="outline" size="lg" className="gap-2" onClick={() => {
                setShowTemplates(false);
                const n: FileNode = { id: generateId(), name: "main.js", type: "file", content: "// ضع كودك هنا\nconsole.log('Hello!');\n", language: "javascript" };
                setFileTree([n]); openFile(n);
              }}>
                <Plus className="w-4 h-4" /> مشروع فارغ جديد
              </Button>
              <p className="text-xs text-muted-foreground">أو ارفع ملفاتك من زر "رفع ملفاتك" أعلاه</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ─── File Tree Renderer ──────────────────────────────────────────
  const renderFileTree = (nodes: FileNode[], depth = 0) => (
    <div className="space-y-0.5">
      {nodes.map((node) => (
        <div key={node.id}>
          <div
            className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs cursor-pointer transition-colors group ${activeTabId === node.id ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"}`}
            style={{ paddingRight: `${depth * 12 + 8}px` }}
            onClick={() => node.type === "folder" ? toggleFolder(node.id) : openFile(node)}
          >
            {node.type === "folder" ? (
              <>{node.isOpen ? <ChevronDown className="w-3 h-3 shrink-0" /> : <ChevronRight className="w-3 h-3 shrink-0" />}<Folder className="w-3.5 h-3.5 shrink-0 text-amber-400" /></>
            ) : (
              <><span className="w-3 shrink-0" /><FileCode className="w-3.5 h-3.5 shrink-0 text-blue-400" /></>
            )}
            <span className="truncate flex-1">{node.name}</span>
            <button onClick={(e) => { e.stopPropagation(); handleDeleteNode(node.id); }} className="opacity-0 group-hover:opacity-100 text-red-400 hover:text-red-300 p-0.5"><X className="w-3 h-3" /></button>
          </div>
          {node.type === "folder" && node.isOpen && node.children && renderFileTree(node.children, depth + 1)}
        </div>
      ))}
    </div>
  );

  const allFilesCount = flattenFiles(fileTree).length;

  // ─── Main IDE Layout ─────────────────────────────────────────────
  return (
    <div className="h-screen bg-background text-foreground flex flex-col overflow-hidden">

      {/* ══ Run Project Modal ══════════════════════════════════════════ */}
      <AnimatePresence>
        {showRunModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
            onClick={(e) => e.target === e.currentTarget && setShowRunModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              transition={{ type: "spring", damping: 20, stiffness: 300 }}
              className="bg-card border border-border rounded-2xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden"
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-card/80 shrink-0">
                <div className="flex items-center gap-3">
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-red-500" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500" />
                    <div className="w-3 h-3 rounded-full bg-green-500" />
                  </div>
                  <div className="flex items-center gap-2">
                    <Play className="w-4 h-4 text-green-400" />
                    <span className="text-sm font-bold">تشغيل المشروع</span>
                    <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full">
                      {projectType === "web" ? "🌐 ويب" : projectType === "python" ? "🐍 Python" : projectType === "node" ? "🟢 Node.js" : "⚙️ كود"}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {runHtml && (
                    <Button size="sm" variant="outline" className="text-xs gap-1 h-7" onClick={handleDownloadZip}>
                      <Download className="w-3 h-3" /> تحميل ZIP
                    </Button>
                  )}
                  <button onClick={() => setShowRunModal(false)} className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-secondary">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Modal Content */}
              <div className="flex-1 min-h-0 overflow-hidden">
                {runHtml ? (
                  <iframe
                    srcDoc={runHtml}
                    className="w-full h-full border-0"
                    sandbox="allow-scripts allow-same-origin allow-forms allow-modals"
                    title="Project Output"
                    style={{ minHeight: "500px" }}
                  />
                ) : (
                  // Python / Other: Show instructions
                  <div className="p-8 space-y-6 overflow-y-auto h-full" dir="rtl">
                    <div className="text-center space-y-3">
                      <div className="w-16 h-16 mx-auto bg-amber-500/10 rounded-2xl flex items-center justify-center">
                        <AlertTriangle className="w-8 h-8 text-amber-400" />
                      </div>
                      <h3 className="text-xl font-bold">
                        {projectType === "python" ? "🐍 مشروع Python" : "⚙️ مشروع"}
                      </h3>
                      <p className="text-muted-foreground">
                        هذا النوع من المشاريع يحتاج إلى تنفيذ على جهازك المحلي
                      </p>
                    </div>
                    <div className="bg-black/40 rounded-xl p-5 text-right space-y-3">
                      <h4 className="font-bold text-sm text-amber-400">خطوات التشغيل على جهازك:</h4>
                      {projectType === "python" ? (
                        <ol className="space-y-2 text-sm text-muted-foreground list-decimal list-inside">
                          <li>حمّل الملفات كـ ZIP (زر التحميل أدناه)</li>
                          <li>فك ضغط الملفات في مجلد على جهازك</li>
                          <li>افتح Terminal/Command Prompt في المجلد</li>
                          <li className="font-mono bg-black/30 px-2 py-1 rounded text-green-400">pip install -r requirements.txt</li>
                          <li className="font-mono bg-black/30 px-2 py-1 rounded text-green-400">python main.py</li>
                        </ol>
                      ) : (
                        <ol className="space-y-2 text-sm text-muted-foreground list-decimal list-inside">
                          <li>حمّل الملفات كـ ZIP</li>
                          <li>فك ضغطها وافتح Terminal في المجلد</li>
                          <li className="font-mono bg-black/30 px-2 py-1 rounded text-green-400">شغّل الملف الرئيسي حسب لغته</li>
                        </ol>
                      )}
                    </div>
                    <div className="flex justify-center">
                      <Button onClick={handleDownloadZip} className="gap-2 bg-green-600 hover:bg-green-700 px-8">
                        <Download className="w-4 h-4" /> تحميل المشروع كـ ZIP
                      </Button>
                    </div>
                  </div>
                )}
              </div>

              {/* Modal Footer */}
              {runHtml && (
                <div className="px-4 py-2 border-t border-border bg-card/50 flex items-center justify-between text-xs text-muted-foreground shrink-0">
                  <div className="flex items-center gap-2 text-green-400">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>المشروع يعمل بنجاح في متصفحك</span>
                  </div>
                  <Button size="sm" onClick={handleDownloadZip} variant="outline" className="text-xs gap-1 h-6">
                    <FolderArchive className="w-3 h-3" /> تحميل ZIP للاستخدام المحلي
                  </Button>
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ══ TOP BAR ════════════════════════════════════════════════════ */}
      <header className="h-11 bg-card border-b border-border flex items-center justify-between px-3 shrink-0">
        <div className="flex items-center gap-2">
          <Link href="/" className="text-muted-foreground hover:text-primary transition-colors px-1.5 py-1 rounded hover:bg-primary/10"><Home className="w-3.5 h-3.5" /></Link>
          <div className="w-px h-4 bg-border" />
          <Link href="/agent" className="flex items-center gap-1 text-muted-foreground hover:text-primary transition-colors px-1.5 py-1 rounded hover:bg-primary/10">
            <Bot className="w-3.5 h-3.5" /><span className="text-[10px] font-bold hidden sm:inline">{t("nav.agent")}</span>
          </Link>
          <Link href="/chat" className="flex items-center gap-1 text-muted-foreground hover:text-primary transition-colors px-1.5 py-1 rounded hover:bg-primary/10">
            <MessageSquare className="w-3.5 h-3.5" /><span className="text-[10px] font-bold hidden sm:inline">{t("nav.chat")}</span>
          </Link>
          <div className="w-px h-4 bg-border" />
          <Code2 className="w-4 h-4 text-primary" />
          <span className="font-heading font-bold text-xs">HAYO IDE</span>
          <span className="text-[9px] text-muted-foreground px-1.5 py-0.5 bg-secondary rounded">BYOC</span>
        </div>

        <div className="flex items-center gap-1">
          {/* ▶ RUN PROJECT — Main CTA */}
          <Button
            size="sm"
            className="h-7 px-3 text-[11px] gap-1.5 bg-green-600 hover:bg-green-700 text-white font-bold shadow-lg shadow-green-600/20"
            onClick={handleRunProject}
            disabled={isRunning || allFilesCount === 0}
          >
            {isRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
            تشغيل
          </Button>

          <div className="w-px h-4 bg-border mx-0.5" />

          {/* AI Fix All */}
          <Button
            variant="outline"
            size="sm"
            className="text-[10px] gap-1 h-7 px-2 text-violet-400 border-violet-400/30 hover:bg-violet-400/10"
            onClick={handleAiFixAll}
            disabled={isFixingAll || isProcessing || allFilesCount === 0}
            title="إصلاح جميع الملفات بالذكاء الاصطناعي"
          >
            {isFixingAll ? <Loader2 className="w-3 h-3 animate-spin" /> : <Wrench className="w-3 h-3" />}
            <span className="hidden sm:inline">AI Fix الكل</span>
          </Button>

          {/* AI Fix (current file) */}
          <Button
            variant="outline"
            size="sm"
            className="text-[10px] gap-1 h-7 px-2 text-amber-400 border-amber-400/30 hover:bg-amber-400/10"
            onClick={handleAiFix}
            disabled={!activeFile || isProcessing || isFixingAll}
            title="إصلاح الملف الحالي"
          >
            {isProcessing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Wrench className="w-3 h-3" />}
            <span className="hidden sm:inline">AI Fix</span>
          </Button>

          <div className="w-px h-4 bg-border mx-0.5" />

          <Button variant="ghost" size="sm" className="text-[10px] gap-1 h-7 px-2" onClick={() => setShowSidebar(!showSidebar)}>
            {showSidebar ? <PanelLeftClose className="w-3 h-3" /> : <PanelLeft className="w-3 h-3" />}
          </Button>
          <Button variant="ghost" size="sm" className="text-[10px] gap-1 h-7 px-2" onClick={() => setShowPreview(!showPreview)}>
            {showPreview ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
            <span className="hidden sm:inline text-[10px]">معاينة</span>
          </Button>
          <Button variant="ghost" size="sm" className="text-[10px] gap-1 h-7 px-2" onClick={() => setShowConsole(!showConsole)}>
            <AlertTriangle className="w-3 h-3" />
            <span className="hidden sm:inline text-[10px]">Console</span>
          </Button>

          <div className="w-px h-4 bg-border mx-0.5" />

          {/* Send to Agent for code generation */}
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2 text-primary border-primary/30 hover:bg-primary/10"
            onClick={() => {
              const allFiles = flattenFiles(fileTree);
              if (allFiles.length === 0) { toast.error("لا توجد ملفات"); return; }
              const byocData = { files: allFiles.map(f => ({ name: f.name, content: f.content, language: f.language || "" })), importedAt: new Date().toISOString(), source: "byoc" };
              localStorage.setItem("hayo-byoc-import", JSON.stringify(byocData));
              toast.success("تم نقل المشروع لوكيل AI");
              window.location.href = "/agent";
            }}
            disabled={allFilesCount === 0}>
            <Bot className="w-3 h-3" /> <span className="hidden sm:inline">وكيل AI</span>
          </Button>

          {/* Build APK */}
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2 text-orange-400 border-orange-400/30 hover:bg-orange-400/10"
            onClick={() => {
              const allFiles = flattenFiles(fileTree);
              if (allFiles.length === 0) { toast.error("لا توجد ملفات"); return; }
              const appCode = allFiles.find(f => f.name.includes("App.tsx") || f.name.includes("App.jsx"))?.content;
              if (!appCode) { toast.error("لم يتم العثور على App.tsx — أضف ملف App.tsx أو App.jsx"); return; }
              localStorage.setItem("hayo-build-import", JSON.stringify({ appName: "BYOC App", code: appCode, files: allFiles }));
              toast.success("تم نقل المشروع لمنشئ التطبيقات");
              window.location.href = "/app-builder";
            }}
            disabled={allFilesCount === 0}>
            <Download className="w-3 h-3" /> <span className="hidden sm:inline">بناء APK</span>
          </Button>

          <div className="w-px h-4 bg-border mx-0.5" />

          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2" onClick={handleCopyAll} disabled={allFilesCount === 0}>
            <Copy className="w-3 h-3" />
          </Button>
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2 text-emerald-400 border-emerald-400/30 hover:bg-emerald-400/10" onClick={handleDownloadZip} disabled={allFilesCount === 0}>
            <FolderArchive className="w-3 h-3" /> ZIP
          </Button>
          <input ref={fileInputRef} type="file" multiple onChange={handleFileUpload} className="hidden"
            accept=".js,.py,.ts,.java,.cpp,.cs,.php,.go,.rs,.sql,.html,.css,.txt,.json,.md,.jsx,.tsx,.yml,.yaml,.xml,.sh,.zip,.rar" />
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2" onClick={() => fileInputRef.current?.click()}>
            <Upload className="w-3 h-3" />
          </Button>
          <Button variant="outline" size="sm" className="text-[10px] gap-1 h-7 px-2 text-blue-400 border-blue-400/30 hover:bg-blue-400/10"
            onClick={() => { setFileTree([]); setOpenTabs([]); setActiveTabId(null); setShowTemplates(true); }}>
            <Plus className="w-3 h-3" />
          </Button>
        </div>
      </header>

      {/* ══ MAIN CONTENT ═══════════════════════════════════════════════ */}
      <div className="flex-1 flex overflow-hidden">
        {/* FILE EXPLORER */}
        {showSidebar && (
          <div className="w-52 border-l border-border bg-card/30 flex flex-col shrink-0">
            <div className="px-3 py-2 border-b border-border flex items-center justify-between">
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">الملفات</span>
              <div className="flex gap-0.5">
                <button onClick={() => setNewItemType("file")} className="p-1 rounded hover:bg-secondary text-muted-foreground hover:text-foreground" title="ملف جديد"><FilePlus className="w-3.5 h-3.5" /></button>
                <button onClick={() => setNewItemType("folder")} className="p-1 rounded hover:bg-secondary text-muted-foreground hover:text-foreground" title="مجلد جديد"><FolderPlus className="w-3.5 h-3.5" /></button>
              </div>
            </div>
            {newItemType && (
              <div className="px-2 py-1.5 border-b border-border flex items-center gap-1">
                {newItemType === "folder" ? <Folder className="w-3 h-3 text-amber-400 shrink-0" /> : <File className="w-3 h-3 text-blue-400 shrink-0" />}
                <input autoFocus value={newItemName} onChange={(e) => setNewItemName(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleCreateItem(); if (e.key === "Escape") setNewItemType(null); }}
                  placeholder={newItemType === "folder" ? "اسم المجلد" : "اسم الملف"}
                  className="flex-1 bg-transparent border-none text-xs outline-none placeholder:text-muted-foreground/50" />
                <button onClick={handleCreateItem} className="text-emerald-400 hover:text-emerald-300"><Plus className="w-3 h-3" /></button>
              </div>
            )}
            <div className="flex-1 overflow-y-auto py-1">{renderFileTree(fileTree)}</div>
            <div className="px-3 py-1.5 border-t border-border text-[10px] text-muted-foreground">{allFilesCount} ملف</div>
          </div>
        )}

        {/* EDITOR + PREVIEW */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Tabs */}
          <div className="h-8 bg-card/50 border-b border-border flex items-center px-1 gap-0.5 overflow-x-auto shrink-0">
            {openTabs.length === 0 ? (
              <span className="text-[10px] text-muted-foreground px-2">افتح ملفاً من القائمة</span>
            ) : openTabs.map((tab) => (
              <div key={tab.fileId}
                className={`flex items-center gap-1 px-2.5 py-1 text-[11px] rounded-t cursor-pointer transition-colors group whitespace-nowrap ${tab.fileId === activeTabId ? "bg-background text-foreground border-t-2 border-primary" : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"}`}
                onClick={() => setActiveTabId(tab.fileId)}>
                <FileCode className="w-3 h-3 shrink-0" />
                <span>{tab.name}</span>
                {tab.modified && <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />}
                <button onClick={(e) => { e.stopPropagation(); closeTab(tab.fileId); }} className="opacity-0 group-hover:opacity-100 hover:text-red-400 p-0.5"><X className="w-2.5 h-2.5" /></button>
              </div>
            ))}
          </div>

          {/* Editor + Live Preview Split */}
          <div className="flex-1 flex min-h-0">
            {/* Editor + Console Column */}
            <div className={`${showPreview ? "w-1/2 border-l border-border" : "flex-1"} flex flex-col min-h-0`}>
              {/* Editor */}
              <div className={`${showConsole ? "flex-1" : "flex-1"} min-h-0`} style={showConsole ? { flex: "1 1 65%" } : {}} dir="ltr">
              {activeFile ? (
                <Editor
                  key={activeTabId}
                  height="100%"
                  language={activeFile.language || "plaintext"}
                  defaultValue={activeFile.content || ""}
                  theme="vs-dark"
                  options={{
                    minimap: { enabled: false },
                    fontSize: 13,
                    fontFamily: "'JetBrains Mono', monospace",
                    lineNumbers: "on",
                    scrollBeyondLastLine: false,
                    wordWrap: "on",
                    padding: { top: 8 },
                    renderLineHighlight: "gutter",
                    automaticLayout: true,
                    tabSize: 2,
                    bracketPairColorization: { enabled: true },
                    guides: { bracketPairs: true },
                    readOnly: false,
                  }}
                  onMount={handleEditorMount}
                  onChange={handleEditorChange}
                />
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-4 p-8" dir="rtl">
                  <Code2 className="w-16 h-16 opacity-10" />
                  <div className="text-center space-y-2">
                    <p className="font-medium">افتح ملفاً من القائمة الجانبية</p>
                    <p className="text-xs text-muted-foreground/60">أو ارفع ملفاتك عبر زر Upload</p>
                  </div>
                </div>
              )}
              </div>

              {/* Console Panel (VS Code style) */}
              {showConsole && (
                <div className="border-t border-border bg-[#0d1117] flex flex-col" style={{ flex: "0 0 35%", minHeight: "120px", maxHeight: "300px" }}>
                  <div className="h-7 bg-[#161b22] border-b border-border flex items-center justify-between px-3 shrink-0">
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-bold text-muted-foreground flex items-center gap-1.5">
                        <AlertTriangle className="w-3 h-3 text-amber-400" /> CONSOLE
                      </span>
                      <span className="text-[9px] px-1.5 py-0.5 bg-muted/30 rounded text-muted-foreground">{consoleOutput.length}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <button onClick={() => setConsoleOutput([{ text: "[HAYO IDE] Console cleared.", type: "system" }])} className="text-muted-foreground hover:text-foreground p-0.5" title="مسح">
                        <X className="w-3 h-3" />
                      </button>
                      <button onClick={() => setShowConsole(false)} className="text-muted-foreground hover:text-foreground p-0.5" title="إخفاء">
                        <Minimize2 className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                  <div className="flex-1 overflow-y-auto font-mono text-[11px] px-3 py-1.5 space-y-0.5" dir="ltr">
                    {consoleOutput.map((entry, i) => (
                      <div key={i} className={`leading-relaxed ${
                        entry.type === "error" ? "text-red-400" :
                        entry.type === "success" ? "text-emerald-400" :
                        entry.type === "system" ? "text-violet-400" :
                        entry.type === "output" ? "text-cyan-300" :
                        "text-gray-400"
                      }`}>
                        {entry.text}
                      </div>
                    ))}
                    <div ref={consoleEndRef} />
                  </div>
                </div>
              )}
            </div>

            {/* Inline Live Preview */}
            {showPreview && (
              <div className="w-1/2 flex flex-col min-h-0 bg-white">
                <div className="h-7 bg-card border-b border-border flex items-center justify-between px-2 shrink-0">
                  <span className="text-[10px] font-bold text-muted-foreground flex items-center gap-1"><Eye className="w-3 h-3" /> معاينة مباشرة</span>
                  <Button variant="ghost" size="sm" className="h-5 text-[9px] gap-1 px-2" onClick={handleRunProject}>
                    <Play className="w-2.5 h-2.5 fill-current text-green-400" /> تشغيل كامل
                  </Button>
                </div>
                <div className="flex-1 min-h-0">
                  {(() => {
                    const html = buildProjectHtml(flattenFiles(fileTree));
                    return html ? (
                      <iframe srcDoc={html} className="w-full h-full border-0" sandbox="allow-scripts allow-same-origin" title="Live Preview" />
                    ) : (
                      <div className="h-full flex items-center justify-center text-gray-400 text-sm">
                        <div className="text-center space-y-2"><Eye className="w-10 h-10 mx-auto opacity-20" /><p>أضف ملف HTML أو JS للمعاينة</p></div>
                      </div>
                    );
                  })()}
                </div>
              </div>
            )}
          </div>

          {/* Status Bar */}
          <div className="h-6 bg-card/50 border-t border-border flex items-center justify-between px-3 text-[10px] text-muted-foreground shrink-0">
            <div className="flex items-center gap-3">
              {(isProcessing || isFixingAll) ? (
                <span className="flex items-center gap-1 text-amber-400"><Loader2 className="w-3 h-3 animate-spin" /> معالجة AI...</span>
              ) : (
                <span className="flex items-center gap-1 text-emerald-400"><Square className="w-2.5 h-2.5 fill-current" /> جاهز</span>
              )}
            </div>
            <div className="flex items-center gap-3">
              <span>{allFilesCount} ملف</span>
              {activeFile && <span className="text-blue-400">{activeFile.language}</span>}
              {activeFile?.content && <span>{activeFile.content.split("\n").length} سطر</span>}
            </div>
          </div>
        </div>

        {/* ══ CONSOLE ═════════════════════════════════════════════════ */}
        <div className="w-56 border-r border-border bg-card/20 flex flex-col shrink-0">
          <div className="px-3 py-2 border-b border-border flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2">
              <div className="flex gap-1">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
                <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              </div>
              <span className="text-[10px] font-mono text-muted-foreground">console</span>
            </div>
            <button onClick={() => setConsoleOutput([{ text: "[HAYO IDE] Console cleared.", type: "system" }])}
              className="text-[9px] text-muted-foreground/50 hover:text-muted-foreground transition-colors">
              مسح
            </button>
          </div>
          <div className="flex-1 overflow-y-auto px-3 py-2 font-mono text-[10px] space-y-0.5 bg-black/20">
            {consoleOutput.map((entry, i) => (
              <div key={i} className={`leading-relaxed break-words ${
                entry.type === "success" ? "text-emerald-400" :
                entry.type === "error" ? "text-red-400" :
                entry.type === "system" ? "text-violet-400" :
                entry.type === "output" ? "text-blue-300" :
                "text-gray-400"
              }`}>{entry.text}</div>
            ))}
            <div ref={consoleEndRef} />
          </div>
        </div>
      </div>
    </div>
  );
}
