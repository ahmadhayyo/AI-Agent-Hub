export interface DecompiledFile {
  path: string;
  name: string;
  extension: string;
  size: number;
  content?: string;
  isBinary: boolean;
}

export interface FileTreeNode {
  name: string;
  path: string;
  type: "file" | "folder";
  size?: number;
  children?: FileTreeNode[];
}

export interface VulnerabilityFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  evidence: string[];
}

export interface DecompileResult {
  success: boolean;
  fileType: string;
  totalFiles: number;
  totalSize: number;
  structure: FileTreeNode[];
  files: DecompiledFile[];
  manifest?: any;
  metadata?: any;
  downloadId?: string;
  error?: string;
  analysisAvailable: boolean;
  vulnerabilities?: VulnerabilityFinding[];
  formatLabel?: string;
}

export interface EditSession {
  sessionId: string;
  structure: FileTreeNode[];
  fileCount: number;
  apkToolAvailable: boolean;
  usedApkTool: boolean;
  fileType?: string;
}

export interface IntelReport {
  ssl: string[];
  root: string[];
  crypto: string[];
  secrets: string[];
  urls: string[];
  summary: string;
}

export interface SmartModifyResult {
  modifications: Array<{
    filePath: string;
    explanation: string;
    originalSnippet: string;
    modifiedSnippet: string;
  }>;
  summary: string;
  filesModified: number;
}

export interface CloneResult {
  modifications: string[];
  patchedFiles?: number;
  signed?: boolean;
  downloadUrl?: string;
  installCommand?: string;
  success?: boolean;
}

export interface CloneOptions {
  removeAds: boolean;
  unlockPremium: boolean;
  removeTracking: boolean;
  removeLicenseCheck: boolean;
  changeAppName: string;
  changePackageName: string;
  customInstructions: string;
}

export interface LiveStreamState {
  sseUrl: string;
}

export interface ForensicsPanelDataFlowApi {
  category: string;
  api: string;
  file: string;
  line: number;
  context: string;
  dataFlow?: string[];
}

export interface ForensicsPanelDataFlow {
  sensitiveApis?: ForensicsPanelDataFlowApi[];
  sinks?: unknown[];
  sources?: unknown[];
}

export interface ForensicsPanelHierarchyClass {
  children: unknown[];
  isInterface?: boolean;
  isAbstract?: boolean;
  name: string;
  methods: number;
  fields: number;
  superClass?: string;
}

export interface ForensicsPanelHierarchy {
  stats: {
    totalClasses: number;
    interfaces: number;
    abstractClasses: number;
    maxDepth: number;
  };
  classes?: ForensicsPanelHierarchyClass[];
}

export interface ForensicsPanelXrefReference {
  type: string;
  file: string;
  line: number;
  context: string;
}

export interface ForensicsPanelXref {
  totalCount: number;
  target: string;
  references?: ForensicsPanelXrefReference[];
}

export interface ForensicsPanelMethod {
  methodName: string;
  signature: string;
  file: string;
  line: number;
  linesOfCode: number;
  registers: number;
  modifiers: string;
}

export interface ForensicsPanelMethodSearch {
  totalFound: number;
  methods?: ForensicsPanelMethod[];
}

export interface ForensicsPanelDiffSummary {
  totalAdded?: number;
  totalRemoved?: number;
  totalModified?: number;
  totalUnchanged?: number;
  versionChange?: { old: string; new: string };
  permissionChanges?: {
    added?: string[];
    removed?: string[];
  };
}

export interface ForensicsPanelDiff {
  summary?: ForensicsPanelDiffSummary;
  added?: string[];
  removed?: string[];
  modified?: Array<{ path: string; sizeDiff: number }>;
}

export interface ForensicsDecodedEntry {
  encoding: string;
  file: string;
  line: number;
  confidence: number;
  original: string;
  decoded: string;
}

export interface CloudPentestSummary {
  riskScore: number;
  criticalCount: number;
  highCount: number;
  extractedKeys?: string[];
  extractedEndpoints?: string[];
  cloudProviders?: string[];
}

export interface CloudPentestStep {
  id: number;
  title: string;
  details?: string;
  status: "critical" | "warning" | "success" | "info";
  findings?: string[];
  commands?: string[];
}

export interface CloudPentestResult {
  fileName?: string;
  fileSize?: number;
  generatedAt: string;
  summary: CloudPentestSummary;
  steps?: CloudPentestStep[];
  report: string;
}
