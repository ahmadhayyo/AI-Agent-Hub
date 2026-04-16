export {
  decompileAPK,
  analyzeEXE,
  analyzeEX4,
  analyzeEX5,
  analyzeELF,
  analyzeIPA,
  analyzeJAR,
  analyzeWASM,
  analyzeDEX,
  diffAPKs,
  readDirRecursive,
} from "./decompilation.js";

export {
  editSessions,
  findApkTool,
  isJavaAvailable,
  isApkToolAvailable,
  getToolStatus,
  decompileAPKForEdit,
  decompileFileForEdit,
  saveFileEdit,
  getSessionInfo,
  readSessionFileContent,
  revertFile,
  rebuildAPK,
  regexSearchFiles,
} from "./edit-session.js";

export {
  analyzeWithAI,
  aiModifyCode,
  aiSearchFiles,
  aiSmartModify,
  aiDecompileSmali,
  aiVulnerabilityScan,
  aiCodeSimilarity,
  activeCloudPentest,
} from "./ai.js";

export { cloneApp } from "./clone.js";

export {
  scanVulnerabilities,
  analyzeCertificate,
  analyzePermissionRisk,
  extractNetworkEndpoints,
  detectObfuscation,
  detectMalwarePatterns,
} from "./security.js";

export {
  decodeStringsInFiles,
  crossReference,
  buildClassHierarchy,
  analyzeDataFlow,
  methodSignatureSearch,
  generateForensicReport,
  extractStringsFromBinary,
  parseDEXHeader,
  parsePEHeaderDetailed,
} from "./forensics.js";

export {
  runCloudPentest,
  generateIntelligenceReport,
} from "./cloud-pentest.js";

export type {
  DecompiledFile,
  VulnerabilityFinding,
  DecompileResult,
  FileTreeNode,
  CloneOptions,
  DecodedString,
  XrefResult,
  ClassNode,
  DiffResult,
  DataFlowResult,
  MethodSearchResult,
  CloudPentestStep,
  CloudPentestResult,
} from "./types.js";
