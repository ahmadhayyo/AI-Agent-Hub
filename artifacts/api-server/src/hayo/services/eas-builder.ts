/**
 * EAS Builder Service — builds Android APK via Expo EAS Build cloud
 * Uses EXPO_ACCESS_TOKEN env var (set as Replit Secret)
 */
import { execSync, spawn } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import JSZip from "jszip";

const EXPO_OWNER = "ahmet80";
const BUILD_DIR_ROOT = path.join(os.tmpdir(), "hayo-builds");

// ── Fixed builder project (reused for all builds to avoid hitting 50-project limit) ──
// Pre-registered project on Expo under ahmet80 account.
// Inject its projectId directly — NO eas init needed.
const BUILDER_PROJECT_ID = process.env.EXPO_PROJECT_ID   || "8b4e647b-ba87-439b-a677-5047702a3ddb";
const BUILDER_SLUG       = process.env.EXPO_PROJECT_SLUG || "haio-ai-agent";

// ── Expo SDK 52 — pinned, known-good package versions ────────────
// React Native 0.76.3 is the exact version shipped with Expo SDK 52.
const EXPO_SDK_VERSION = "~52.0.0";
const REACT_NATIVE_VERSION = "0.76.3";

// ── Resolve EAS CLI path ─────────────────────────────────────────

function getNpmGlobalBin(): string {
  try {
    const root = execSync("npm root -g 2>/dev/null", { stdio: "pipe" }).toString().trim();
    if (root) return root.replace(/[\\/]lib[\\/]node_modules$/, "/bin").replace(/\\/g, "/");
  } catch {}
  for (const p of [
    "/home/runner/workspace/.config/npm/node_global/bin",
    "/root/.config/npm/node_global/bin",
    "/usr/local/bin",
  ]) {
    if (fs.existsSync(p)) return p;
  }
  return "/usr/local/bin";
}

function resolveEasBin(): string {
  try {
    const fromPath = execSync("which eas 2>/dev/null", { stdio: "pipe" }).toString().trim();
    if (fromPath && fs.existsSync(fromPath)) return fromPath;
  } catch {}
  const globalBin = path.join(getNpmGlobalBin(), "eas");
  if (fs.existsSync(globalBin)) return globalBin;
  for (const p of ["/usr/local/bin/eas", "/usr/bin/eas"]) {
    if (fs.existsSync(p)) return p;
  }
  return "eas";
}

function ensureEasInstalled(): string {
  let bin = resolveEasBin();
  if (bin !== "eas" && fs.existsSync(bin)) return bin;
  console.log("[EAS Builder] EAS CLI not found — installing...");
  try {
    execSync("npm install -g eas-cli@latest 2>&1", {
      stdio: "pipe", timeout: 120_000, env: { ...process.env },
    });
  } catch (e: any) {
    console.error("[EAS Builder] Failed to install EAS CLI:", e.message?.slice(0, 200));
  }
  bin = resolveEasBin();
  console.log("[EAS Builder] Using EAS binary:", bin);
  return bin;
}

function buildEnvPath(): string {
  const existing = process.env.PATH || "";
  const npmBin = getNpmGlobalBin();
  return existing.includes(npmBin) ? existing : `${npmBin}:${existing}`;
}

// ── Types ────────────────────────────────────────────────────────

export interface BuildResult {
  expoJobId: string;
  expoSlug: string;
  buildLogsUrl: string;
}

export interface BuildStatus {
  status: "queued" | "in_progress" | "finished" | "errored" | "cancelled";
  downloadUrl?: string;
  errorMessage?: string;
  buildLogsUrl?: string;
}

// ── Init ─────────────────────────────────────────────────────────

if (!fs.existsSync(BUILD_DIR_ROOT)) {
  fs.mkdirSync(BUILD_DIR_ROOT, { recursive: true });
}

function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 30);
}

// ── Standard Expo SDK 52 dependencies ───────────────────────────

function getBaseDeps(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "expo":                                    EXPO_SDK_VERSION,
    "react":                                   "18.3.1",
    "react-native":                            REACT_NATIVE_VERSION,
    "@expo/vector-icons":                      "~14.0.4",
    "expo-status-bar":                         "~2.0.0",
    "expo-clipboard":                          "~7.0.0",
    "expo-linear-gradient":                    "~14.0.0",
    "expo-haptics":                            "~14.0.0",
    "expo-blur":                               "~14.0.0",
    "@react-native-async-storage/async-storage": "2.1.0",
    "expo-file-system":                        "~18.0.0",
    "expo-sharing":                            "~13.0.0",
    "expo-image-picker":                       "~16.0.0",
    "expo-camera":                             "~16.0.0",
    "expo-location":                           "~18.0.0",
    "expo-device":                             "~7.0.0",
    "expo-sensors":                            "~14.0.0",
    "expo-notifications":                      "~0.29.0",
    "expo-web-browser":                        "~14.0.0",
    "expo-linking":                            "~7.0.0",
    "expo-build-properties":                   "~0.13.0",
    ...extra,
  };
}

function getDevDeps(): Record<string, string> {
  return {
    "@babel/core":  "^7.24.0",
    "@types/react": "~18.3.12",
    "typescript":   "^5.3.3",
  };
}

// ── Standard project files ───────────────────────────────────────

function writeStandardFiles(projectDir: string, slug: string, appName: string, hasIcon: boolean, extraDeps: Record<string, string> = {}) {
  // Always use the registered BUILDER_SLUG for Expo — the projectId is linked to this slug.
  // Use a unique package name per app so multiple apps can be installed side-by-side.
  const pkg = `com.hayo.${slug.replace(/-/g, "").slice(0, 30)}`;

  const appJson: any = {
    expo: {
      name:           appName,
      slug:           BUILDER_SLUG,
      version:        "1.0.0",
      sdkVersion:     "52.0.0",
      orientation:    "portrait",
      owner:          EXPO_OWNER,
      platforms:      ["android"],
      android: {
        package:       pkg,
        adaptiveIcon:  { backgroundColor: "#1a1a2e" },
        versionCode:   1,
      },
      newArchEnabled: false,
      plugins: [
        ["expo-build-properties", {
          android: {
            compileSdkVersion: 35,
            targetSdkVersion: 34,
            minSdkVersion: 24,
            buildToolsVersion: "35.0.0",
            kotlinVersion: "1.9.25",
          },
        }],
      ],
      extra:          { eas: { projectId: BUILDER_PROJECT_ID } },
    },
  };

  if (hasIcon) {
    appJson.expo.icon = "./assets/icon.png";
    appJson.expo.android.adaptiveIcon.foregroundImage = "./assets/icon.png";
  }

  fs.writeFileSync(path.join(projectDir, "app.json"), JSON.stringify(appJson, null, 2));

  fs.writeFileSync(path.join(projectDir, "package.json"), JSON.stringify({
    name:    slug,
    version: "1.0.0",
    main:    "index.js",
    scripts: { start: "expo start" },
    dependencies:    getBaseDeps(extraDeps),
    devDependencies: getDevDeps(),
  }, null, 2));

  fs.writeFileSync(path.join(projectDir, "tsconfig.json"),
    JSON.stringify({ extends: "expo/tsconfig.base", compilerOptions: { strict: true } }, null, 2));

  fs.writeFileSync(path.join(projectDir, "eas.json"), JSON.stringify({
    cli:   { version: ">= 10.0.0", appVersionSource: "local" },
    build: {
      production: {
        android: {
          buildType: "apk",
          credentialsSource: "remote",
          image: "latest",
        },
      },
    },
  }, null, 2));

  fs.writeFileSync(path.join(projectDir, "babel.config.js"),
    `module.exports = function(api) { api.cache(true); return { presets: ['babel-preset-expo'] }; };\n`);

  fs.writeFileSync(path.join(projectDir, "index.js"),
    `import { registerRootComponent } from 'expo';\nimport App from './App';\nregisterRootComponent(App);\n`);

  fs.writeFileSync(path.join(projectDir, ".gitignore"),
    `node_modules/\n.expo/\ndist/\n*.tsbuildinfo\n`);
}

// ── Install node_modules (needed for EAS CLI to resolve plugins) ──
// Full install so expo-config can resolve plugins locally before upload.

function installDependencies(projectDir: string): void {
  console.log("[EAS Builder] Installing node_modules...");
  try {
    execSync(
      "npm install --no-audit --no-fund --legacy-peer-deps 2>&1",
      {
        cwd: projectDir,
        env: { ...process.env, HOME: process.env.HOME || "/root", PATH: buildEnvPath() },
        stdio: "pipe",
        timeout: 180_000,
      }
    );
    console.log("[EAS Builder] node_modules installed ✅");
  } catch (e: any) {
    const msg = e.stdout?.toString() || e.stderr?.toString() || e.message || "";
    console.error("[EAS Builder] npm install failed:", msg.slice(0, 500));
    throw new Error(`فشل تثبيت الحزم: ${msg.slice(0, 200)}`);
  }

  const pluginPath = path.join(projectDir, "node_modules", "expo-build-properties");
  if (!fs.existsSync(pluginPath)) {
    console.warn("[EAS Builder] expo-build-properties not found after install — build may fail");
  }
}

// ── Git helpers ───────────────────────────────────────────────────

function makeGitEnv() {
  return {
    ...process.env,
    HOME:                  process.env.HOME || "/root",
    PATH:                  buildEnvPath(),
    GIT_AUTHOR_NAME:       "HAYO AI",
    GIT_AUTHOR_EMAIL:      "build@hayo.ai",
    GIT_COMMITTER_NAME:    "HAYO AI",
    GIT_COMMITTER_EMAIL:   "build@hayo.ai",
  };
}

function gitInitAndCommit(projectDir: string, message = "init"): void {
  const env = makeGitEnv();
  try {
    execSync('git config --global user.email "build@hayo.ai" && git config --global user.name "HAYO AI"', { env, stdio: "pipe" });
  } catch {}
  execSync("git init",             { cwd: projectDir, env, stdio: "pipe" });
  execSync("git add -A",           { cwd: projectDir, env, stdio: "pipe" });
  execSync(`git commit -m '${message}'`, { cwd: projectDir, env, stdio: "pipe" });
}

function gitCommitUpdate(projectDir: string, message = "update"): void {
  const env = makeGitEnv();
  try {
    execSync(`git add -A && git commit -m '${message}' --allow-empty`, { cwd: projectDir, env, stdio: "pipe" });
  } catch {}
}

// ════════════════════════════════════════════════════════════════
// createExpoProject — generate project from AI-written App.tsx
// ════════════════════════════════════════════════════════════════

export async function createExpoProject(
  appName: string,
  appCode: string,
  iconUrl?: string,
  options?: {
    extraPackages?: string[];
    embeddedData?: Array<{ filename: string; content: string }>;
    supabaseUrl?: string;
    supabaseKey?: string;
    customKeystoreBase64?: string;
  },
): Promise<{ projectDir: string; slug: string }> {
  const uid = crypto.randomBytes(4).toString("hex");
  const slug = `hayo-${slugify(appName)}-${uid}`;
  const projectDir = path.join(BUILD_DIR_ROOT, slug);

  fs.mkdirSync(projectDir, { recursive: true });
  fs.mkdirSync(path.join(projectDir, "assets"), { recursive: true });
  fs.mkdirSync(path.join(projectDir, "data"),   { recursive: true });

  // Download icon
  let hasIcon = false;
  if (iconUrl) {
    try {
      const iconRes = await fetch(iconUrl, { signal: AbortSignal.timeout(15_000) });
      if (iconRes.ok) {
        fs.writeFileSync(path.join(projectDir, "assets", "icon.png"), Buffer.from(await iconRes.arrayBuffer()));
        hasIcon = true;
        console.log(`[EAS] Icon downloaded from ${iconUrl}`);
      }
    } catch (e) { console.warn(`[EAS] Icon download failed: ${e}`); }
  }

  // Extra packages requested
  const extraDeps: Record<string, string> = {};
  if (options?.supabaseUrl) extraDeps["@supabase/supabase-js"] = "^2.45.0";
  if (options?.extraPackages) {
    for (const pkg of options.extraPackages) {
      if (!pkg.includes(" ")) extraDeps[pkg] = "latest";
    }
  }

  // Write all standard project files
  writeStandardFiles(projectDir, slug, appName, hasIcon, extraDeps);

  // Embedded data files
  if (options?.embeddedData?.length) {
    for (const d of options.embeddedData) {
      const safeName = d.filename.replace(/[^a-zA-Z0-9._-]/g, "_");
      fs.writeFileSync(path.join(projectDir, "data", safeName), d.content);
    }
  }

  // Supabase config
  if (options?.supabaseUrl && options?.supabaseKey) {
    fs.writeFileSync(path.join(projectDir, "supabase.ts"),
      `import { createClient } from '@supabase/supabase-js';\nexport const supabase = createClient('${options.supabaseUrl}', '${options.supabaseKey}');\n`);
  }

  // Custom keystore (local signing)
  if (options?.customKeystoreBase64) {
    fs.writeFileSync(path.join(projectDir, "release.keystore"), Buffer.from(options.customKeystoreBase64, "base64"));
    const easJson = JSON.parse(fs.readFileSync(path.join(projectDir, "eas.json"), "utf-8"));
    easJson.build.production.android.credentialsSource = "local";
    fs.writeFileSync(path.join(projectDir, "eas.json"), JSON.stringify(easJson, null, 2));
    fs.writeFileSync(path.join(projectDir, "credentials.json"), JSON.stringify({
      android: { keystore: { keystorePath: "release.keystore", keystorePassword: "hayo123", keyAlias: "hayo", keyPassword: "hayo123" } },
    }, null, 2));
  }

  // App code
  fs.writeFileSync(path.join(projectDir, "App.tsx"), appCode);

  return { projectDir, slug };
}

// ════════════════════════════════════════════════════════════════
// submitEASBuild — prepare git repo + run eas build --no-wait
// ════════════════════════════════════════════════════════════════

export async function submitEASBuild(projectDir: string, slug: string): Promise<BuildResult> {
  const token = process.env.EXPO_ACCESS_TOKEN;
  if (!token) throw new Error("EXPO_ACCESS_TOKEN غير موجود — يرجى إضافته في Secrets من لوحة تحكم Replit (القائمة الجانبية → Secrets → أضف EXPO_ACCESS_TOKEN). يمكنك الحصول عليه من https://expo.dev/accounts/settings");

  const easBin = ensureEasInstalled();
  console.log(`[EAS Builder] Using EAS binary: ${easBin}`);

  // Install dependencies (EAS CLI needs node_modules to resolve config/plugins)
  installDependencies(projectDir);

  // Git init & commit (includes lockfile)
  try {
    gitInitAndCommit(projectDir, "init");
  } catch (gitErr: any) {
    const msg = gitErr.stderr?.toString() || gitErr.stdout?.toString() || gitErr.message;
    throw new Error(`فشل تهيئة git: ${msg}`);
  }

  const easEnv = {
    ...process.env,
    HOME:                       process.env.HOME || "/root",
    PATH:                       buildEnvPath(),
    EXPO_TOKEN:                 token,
    CI:                         "1",
    EXPO_DEBUG:                 "0",
    EAS_BUILD_NO_EXPO_GO_WARNING: "true",
    GIT_AUTHOR_NAME:            "HAYO AI",
    GIT_AUTHOR_EMAIL:           "build@hayo.ai",
    GIT_COMMITTER_NAME:         "HAYO AI",
    GIT_COMMITTER_EMAIL:        "build@hayo.ai",
  };

  return new Promise((resolve, reject) => {
    console.log(`[EAS Builder] Submitting build for ${slug}...`);

    const cmd = spawn(
      easBin,
      ["build", "--platform", "android", "--profile", "production", "--non-interactive", "--no-wait", "--json"],
      { cwd: projectDir, env: easEnv, shell: false }
    );

    let stdout = "";
    let stderr = "";

    cmd.stdout.on("data", (d: Buffer) => {
      const chunk = d.toString();
      stdout += chunk;
      // Stream relevant lines to console for debugging
      if (chunk.trim()) console.log("[EAS stdout]", chunk.trim().slice(0, 200));
    });
    cmd.stderr.on("data", (d: Buffer) => {
      const chunk = d.toString();
      stderr += chunk;
      if (chunk.trim() && !chunk.includes("DeprecationWarning")) {
        console.warn("[EAS stderr]", chunk.trim().slice(0, 200));
      }
    });

    cmd.on("close", (code) => {
      const combined = stdout + stderr;

      // Try JSON output first
      const jsonMatch = stdout.match(/\[[\s\S]*?\]|\{[\s\S]*?\}/);
      if (jsonMatch) {
        try {
          const parsed = JSON.parse(jsonMatch[0]);
          const buildInfo = Array.isArray(parsed) ? parsed[0] : parsed;
          if (buildInfo?.id) {
            return resolve({
              expoJobId:    buildInfo.id,
              expoSlug:     slug,
              buildLogsUrl: `https://expo.dev/accounts/${EXPO_OWNER}/projects/${BUILDER_SLUG}/builds/${buildInfo.id}`,
            });
          }
        } catch {}
      }

      // Fallback: extract build ID from URL patterns in output
      const urlMatch = combined.match(/builds\/([a-f0-9-]{36})/);
      if (urlMatch) {
        const expoJobId = urlMatch[1];
        return resolve({
          expoJobId,
          expoSlug:     slug,
          buildLogsUrl: `https://expo.dev/accounts/${EXPO_OWNER}/projects/${BUILDER_SLUG}/builds/${expoJobId}`,
        });
      }

      // Detect common human-readable errors
      const knownErrors = [
        ["project limit", "وصل الحساب للحد الأقصى من المشاريع (50). يرجى حذف مشاريع قديمة من expo.dev"],
        ["not logged in", "غير مسجّل الدخول — تحقق من EXPO_ACCESS_TOKEN"],
        ["invalid token", "رمز EXPO_ACCESS_TOKEN غير صالح"],
        ["rate limit", "تجاوز حد معدل الطلبات — انتظر قليلاً ثم أعد المحاولة"],
        ["ENOTFOUND", "لا يوجد اتصال بالإنترنت"],
      ];
      for (const [pattern, msg] of knownErrors) {
        if (combined.toLowerCase().includes(pattern)) {
          return reject(new Error(msg));
        }
      }

      reject(new Error(`فشل إرسال البناء (exit ${code}):\n${(stderr || stdout).slice(0, 600)}`));
    });

    setTimeout(() => {
      cmd.kill();
      reject(new Error("انتهت مهلة إرسال البناء (3 دقائق) — حاول مجدداً"));
    }, 180_000);
  });
}

// ════════════════════════════════════════════════════════════════
// checkEASBuildStatus — poll Expo API for build result
// ════════════════════════════════════════════════════════════════

export async function checkEASBuildStatus(expoJobId: string, expoSlug?: string): Promise<BuildStatus> {
  const token = process.env.EXPO_ACCESS_TOKEN;
  if (!token) throw new Error("EXPO_ACCESS_TOKEN غير موجود — يرجى إضافته في Secrets من لوحة تحكم Replit");

  const query = `{
    builds {
      byId(buildId: "${expoJobId}") {
        id status
        artifacts { buildUrl }
        error { message }
      }
    }
  }`;

  const res = await fetch("https://api.expo.dev/graphql", {
    method: "POST",
    headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });

  if (!res.ok) throw new Error(`Expo GraphQL error ${res.status}: ${res.statusText}`);

  const json = await res.json() as any;
  let build = json?.data?.builds?.byId;

  // Fallback: query account-level builds
  if (!build && !json.errors?.length) {
    const fallbackQuery = `{ account { byName(accountName: "${EXPO_OWNER}") { builds(limit: 20, offset: 0) { id status artifacts { buildUrl } error { message } } } } }`;
    const fb = await fetch("https://api.expo.dev/graphql", {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ query: fallbackQuery }),
    });
    if (fb.ok) {
      const fbJson = await fb.json() as any;
      const builds: any[] = fbJson?.data?.account?.byName?.builds || [];
      build = builds.find((b: any) => b.id === expoJobId) || builds[0];
    }
  }

  if (!build) return { status: "in_progress" };

  const rawStatus = (build.status || "").toUpperCase();
  const status: BuildStatus["status"] =
    rawStatus === "FINISHED"                              ? "finished"
    : rawStatus === "ERRORED" || rawStatus === "EXPIRED" ? "errored"
    : rawStatus === "CANCELLED"                          ? "cancelled"
    : rawStatus === "IN_PROGRESS"                        ? "in_progress"
    : "queued";

  return {
    status,
    downloadUrl:  build.artifacts?.buildUrl || undefined,
    errorMessage: build.error?.message || undefined,
    buildLogsUrl: `https://expo.dev/accounts/${EXPO_OWNER}/projects/${BUILDER_SLUG}/builds/${expoJobId}`,
  };
}

export function cleanupProjectDir(projectDir: string) {
  try { fs.rmSync(projectDir, { recursive: true, force: true }); } catch {}
}

// ════════════════════════════════════════════════════════════════
// AI Code Review & Fix — dual-model pipeline
// ════════════════════════════════════════════════════════════════

export async function aiReviewAndFix(
  code: string,
  errorLog?: string
): Promise<{ fixedCode: string; issues: string[]; modelUsed: string; validatorModel: string }> {
  const { callPowerAI, callFastAI } = await import("../providers.js");

  const ALLOWED_PACKAGES = `
الحزم المتاحة في package.json:
- react-native core (View, Text, TouchableOpacity, ScrollView, FlatList, Image, TextInput, etc.)
- @expo/vector-icons (Ionicons, MaterialIcons, FontAwesome, AntDesign, Feather)
- expo-status-bar → import { StatusBar } from 'expo-status-bar'
- expo-clipboard → import * as Clipboard from 'expo-clipboard'
- expo-linear-gradient → import { LinearGradient } from 'expo-linear-gradient'
- expo-haptics → import * as Haptics from 'expo-haptics'
- expo-blur → import { BlurView } from 'expo-blur'
- @react-native-async-storage/async-storage → import AsyncStorage from '@react-native-async-storage/async-storage'
- expo-file-system → import * as FileSystem from 'expo-file-system'
- expo-sharing → import * as Sharing from 'expo-sharing'
- expo-image-picker → import * as ImagePicker from 'expo-image-picker'
- expo-camera → import { CameraView, useCameraPermissions } from 'expo-camera'
- expo-location → import * as Location from 'expo-location'
- expo-device → import * as Device from 'expo-device'
- expo-sensors → import { Accelerometer, Gyroscope, Barometer } from 'expo-sensors'
- expo-notifications → import * as Notifications from 'expo-notifications'
- expo-web-browser → import * as WebBrowser from 'expo-web-browser'
- expo-linking → import * as Linking from 'expo-linking'`;

  const RULES = `قواعد صارمة لا تُخالَف:
1. أعد الكود المُصلح كاملاً (ليس فقط التغييرات)
2. استخدم الحزم المتاحة فقط — لا تستورد حزمة غير مذكورة أعلاه
3. ممنوع: react-navigation, expo-router, expo-av, react-native-maps, expo-font, useFonts
4. ممنوع: import { Clipboard } from 'react-native' — استخدم expo-clipboard
5. ممنوع: import { StatusBar } from 'react-native' — استخدم expo-status-bar
6. ممنوع: fontFamily بقيم غير آمنة (Arial, Helvetica, Georgia) — استخدم sans-serif أو serif أو monospace
7. ممنوع: registerRootComponent في App.tsx — يوجد في index.js منفصل
8. الملف يجب أن يبدأ بـ import React من 'react' وينتهي بـ export default
9. كل الكود في ملف App.tsx واحد فقط

${ALLOWED_PACKAGES}`;

  // PHASE 1: Fix code (DeepSeek Chat — fast and reliable)
  const fixPrompt = `أنت مطور React Native/Expo محترف. مهمتك إصلاح كود الـ App.tsx.\n\n${RULES}\n\nأعد JSON فقط:\n{"fixedCode": "الكود المصلح كاملاً", "issues": ["مشكلة 1", "مشكلة 2"]}`;
  const fixMsg = errorLog
    ? `فشل البناء بهذا الخطأ:\n--- ERROR ---\n${errorLog.substring(0, 3000)}\n--- END ---\n\nالكود:\n\`\`\`tsx\n${code.substring(0, 25000)}\n\`\`\`\n\nأصلح الأخطاء وأعد الكود كاملاً بصيغة JSON.`
    : `افحص وأصلح هذا الكود:\n\`\`\`tsx\n${code.substring(0, 25000)}\n\`\`\``;

  const phase1 = await callPowerAI(fixPrompt, fixMsg, 16000);
  let fixedCode = code;
  let issues: string[] = [];
  let modelUsed = phase1.modelUsed;

  try {
    const cleaned = phase1.content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      fixedCode = parsed.fixedCode || code;
      fixedCode = fixedCode.replace(/^```(?:tsx?|javascript|jsx)?\n?/i, "").replace(/\n?```\s*$/i, "").trim();
      issues = parsed.issues || [];
    }
  } catch {
    // Fallback: extract code block
    const codeMatch = phase1.content.match(/```tsx?\n([\s\S]*?)```/);
    if (codeMatch) fixedCode = codeMatch[1].trim();
  }

  // PHASE 2: Validate (DeepSeek Fast — quick sanity check)
  let validatorModel = "deepseek-chat";
  try {
    const validatePrompt = `أنت مدقق كود React Native/Expo. افحص هذا الكود وأصلح أي مشكلة نهائية.\n\n${RULES}\n\nأعد JSON فقط:\n{"fixedCode": "الكود النهائي", "extraIssues": ["مشكلة إضافية"]}`;

    const phase2Raw = await callFastAI(
      validatePrompt,
      `دقق هذا الكود:\n\`\`\`tsx\n${fixedCode.substring(0, 20000)}\n\`\`\``,
      8000
    );
    validatorModel = phase2Raw.modelUsed || "deepseek-chat";

    const cleaned2 = phase2Raw.content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const json2 = cleaned2.match(/\{[\s\S]*\}/);
    if (json2) {
      const parsed2 = JSON.parse(json2[0]);
      if (parsed2.fixedCode && parsed2.fixedCode.length > 100) {
        fixedCode = parsed2.fixedCode.replace(/^```(?:tsx?|javascript|jsx)?\n?/i, "").replace(/\n?```\s*$/i, "").trim();
      }
      if (parsed2.extraIssues?.length) {
        issues.push(...parsed2.extraIssues.map((i: string) => `[تدقيق] ${i}`));
      }
    }
  } catch (e: any) {
    console.warn("[aiReviewAndFix] Phase 2 failed (non-fatal):", e.message?.slice(0, 100));
  }

  // PHASE 3: Deterministic safety post-processing
  // Remove expo-font (crashes if fonts aren't loaded)
  fixedCode = fixedCode.replace(/^import \* as Font from ['"]expo-font['"];?\n?/gm, "");
  fixedCode = fixedCode.replace(/^import \{[^}]*useFonts[^}]*\} from ['"]expo-font['"];?\n?/gm, "");
  fixedCode = fixedCode.replace(/const \[fontsLoaded[^\]]*\][^;]*;?\s*\n?/g, "");
  fixedCode = fixedCode.replace(/if\s*\(!?fontsLoaded\)\s*\{?\s*return\s+null\s*;?\s*\}?\s*\n?/g, "");
  // Fix react-native Clipboard → expo-clipboard
  if (/import \{ Clipboard \} from ['"]react-native['"]/.test(fixedCode)) {
    fixedCode = fixedCode.replace(/import \{ Clipboard \} from ['"]react-native['"]/g, "import * as Clipboard from 'expo-clipboard'");
    fixedCode = fixedCode.replace(/Clipboard\.getString\(\)/g, "Clipboard.getStringAsync()");
  }
  // Fix react-native StatusBar → expo-status-bar
  fixedCode = fixedCode.replace(
    /import \{ StatusBar \} from ['"]react-native['"]/g,
    "import { StatusBar } from 'expo-status-bar'"
  );
  // Fix unsafe fontFamily
  for (const font of ["Arial", "Helvetica", "Georgia", "Times New Roman", "Courier New", "Verdana", "Tahoma"]) {
    fixedCode = fixedCode.replace(new RegExp(`fontFamily:\\s*['"]${font}['"]`, "g"), "fontFamily: 'sans-serif'");
  }

  if (!fixedCode || fixedCode.length < 50) fixedCode = code;

  return { fixedCode, issues, modelUsed, validatorModel };
}

// ════════════════════════════════════════════════════════════════
// createExpoProjectFromUpload — from user-uploaded ZIP/files
// ════════════════════════════════════════════════════════════════

export async function createExpoProjectFromUpload(
  files: Array<{ name: string; content: string }>,
  appName: string,
  iconUrl?: string,
): Promise<{ projectDir: string; slug: string; fixLog: string[] }> {
  const uid = crypto.randomBytes(4).toString("hex");
  const slug = `hayo-${slugify(appName)}-${uid}`;
  const projectDir = path.join(BUILD_DIR_ROOT, slug);
  const fixLog: string[] = [];

  fs.mkdirSync(projectDir, { recursive: true });
  fs.mkdirSync(path.join(projectDir, "assets"), { recursive: true });

  // Download icon
  let hasIcon = false;
  if (iconUrl) {
    try {
      const iconRes = await fetch(iconUrl, { signal: AbortSignal.timeout(15000) });
      if (iconRes.ok) {
        fs.writeFileSync(path.join(projectDir, "assets", "icon.png"), Buffer.from(await iconRes.arrayBuffer()));
        hasIcon = true;
        fixLog.push("✅ تم تحميل الأيقونة");
      }
    } catch { fixLog.push("⚠️ فشل تحميل الأيقونة"); }
  }

  // Find App.tsx
  let appTsx = files.find(f => ["App.tsx", "App.jsx", "app.tsx"].includes(f.name))
    || files.find(f => f.name.endsWith("/App.tsx") || f.name.endsWith("/App.jsx"));

  if (!appTsx) {
    const codeFiles = files.filter(f => /\.(tsx|jsx|ts|js)$/.test(f.name));
    if (codeFiles.length === 1) {
      appTsx = { name: "App.tsx", content: codeFiles[0].content };
      fixLog.push("📝 ملف واحد — استخدمه كـ App.tsx");
    } else {
      throw new Error("لم يتم العثور على App.tsx في الملفات المرفوعة");
    }
  }

  // AI review
  fixLog.push("🤖 جاري فحص الكود بنموذجين AI...");
  const review = await aiReviewAndFix(appTsx.content);
  const fixerIssues    = review.issues.filter(i => !i.startsWith("[تدقيق]"));
  const validatorIssues = review.issues.filter(i =>  i.startsWith("[تدقيق]"));
  fixLog.push(`🧠 AI#1 (${review.modelUsed}): ${fixerIssues.length} مشكلة تم إصلاحها`);
  fixLog.push(`🔍 AI#2 (${review.validatorModel}): ${validatorIssues.length} مشكلة إضافية`);
  for (const issue of review.issues) fixLog.push(`  🔧 ${issue}`);

  fs.writeFileSync(path.join(projectDir, "App.tsx"), review.fixedCode);

  // Write other uploaded files
  const skipPatterns = ["node_modules/", ".git/", "dist/", "build/", ".expo/", ".cache/"];
  for (const file of files) {
    if (["App.tsx", "App.jsx", "app.tsx", "package.json", "app.json"].includes(file.name)) continue;
    if (skipPatterns.some(p => file.name.includes(p))) continue;
    if (!file.content || file.content.length > 500000) continue;
    const filePath = path.join(projectDir, file.name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, file.content);
  }

  // Merge safe deps from uploaded package.json
  const extraDeps: Record<string, string> = {};
  const hasPackageJson = files.find(f => f.name === "package.json");
  if (hasPackageJson) {
    try {
      const uploadedPkg = JSON.parse(hasPackageJson.content);
      const blocked = ["react-navigation", "expo-router", "expo-av", "react-native-maps", "expo-font"];
      const allUploadedDeps = { ...uploadedPkg.dependencies, ...uploadedPkg.devDependencies };
      for (const [name, ver] of Object.entries(allUploadedDeps)) {
        if (!blocked.some(b => name.includes(b)) && !getBaseDeps()[name]) {
          extraDeps[name] = ver as string;
          fixLog.push(`📦 تبعية مضافة: ${name}`);
        }
      }
    } catch { fixLog.push("⚠️ فشل قراءة package.json المرفوع"); }
  }

  writeStandardFiles(projectDir, slug, appName, hasIcon, extraDeps);
  fixLog.push("✅ مشروع Expo جاهز للبناء");

  return { projectDir, slug, fixLog };
}

// ════════════════════════════════════════════════════════════════
// submitEASBuildWithRetry — retries with AI fix on failure
// Separates init (done once) from build submission (can retry)
// ════════════════════════════════════════════════════════════════

export async function submitEASBuildWithRetry(
  projectDir: string,
  slug: string,
  appCode: string,
  maxRetries = 2
): Promise<BuildResult & { retries: number; fixLog: string[] }> {
  const fixLog: string[] = [];
  let lastError = "";
  let currentCode = appCode;

  // Phase 0: install dependencies ONCE before first attempt
  installDependencies(projectDir);

  // Phase 0: git init ONCE
  try {
    gitInitAndCommit(projectDir, "init");
  } catch (gitErr: any) {
    const msg = gitErr.stderr?.toString() || gitErr.stdout?.toString() || gitErr.message;
    throw new Error(`فشل تهيئة git: ${msg}`);
  }

  const token = process.env.EXPO_ACCESS_TOKEN;
  if (!token) throw new Error("EXPO_ACCESS_TOKEN غير موجود — يرجى إضافته في Secrets من لوحة تحكم Replit (القائمة الجانبية → Secrets → أضف EXPO_ACCESS_TOKEN). يمكنك الحصول عليه من https://expo.dev/accounts/settings");
  const easBin = ensureEasInstalled();

  const easEnv = {
    ...process.env,
    HOME:                       process.env.HOME || "/root",
    PATH:                       buildEnvPath(),
    EXPO_TOKEN:                 token,
    CI:                         "1",
    EXPO_DEBUG:                 "0",
    EAS_BUILD_NO_EXPO_GO_WARNING: "true",
    GIT_AUTHOR_NAME:            "HAYO AI",
    GIT_AUTHOR_EMAIL:           "build@hayo.ai",
    GIT_COMMITTER_NAME:         "HAYO AI",
    GIT_COMMITTER_EMAIL:        "build@hayo.ai",
  };

  const runBuild = (): Promise<BuildResult> =>
    new Promise((resolve, reject) => {
      const cmd = spawn(
        easBin,
        ["build", "--platform", "android", "--profile", "production", "--non-interactive", "--no-wait", "--json"],
        { cwd: projectDir, env: easEnv, shell: false }
      );

      let stdout = "";
      let stderr = "";
      cmd.stdout.on("data", (d: Buffer) => { const c = d.toString(); stdout += c; if (c.trim()) console.log("[EAS]", c.trim().slice(0, 200)); });
      cmd.stderr.on("data", (d: Buffer) => { const c = d.toString(); stderr += c; if (c.trim() && !c.includes("DeprecationWarning")) console.warn("[EAS stderr]", c.trim().slice(0, 200)); });

      cmd.on("close", (code) => {
        const combined = stdout + stderr;
        const jsonMatch = stdout.match(/\[[\s\S]*?\]|\{[\s\S]*?\}/);
        if (jsonMatch) {
          try {
            const parsed = JSON.parse(jsonMatch[0]);
            const b = Array.isArray(parsed) ? parsed[0] : parsed;
            if (b?.id) return resolve({ expoJobId: b.id, expoSlug: slug, buildLogsUrl: `https://expo.dev/accounts/${EXPO_OWNER}/projects/${BUILDER_SLUG}/builds/${b.id}` });
          } catch {}
        }
        const urlMatch = combined.match(/builds\/([a-f0-9-]{36})/);
        if (urlMatch) return resolve({ expoJobId: urlMatch[1], expoSlug: slug, buildLogsUrl: `https://expo.dev/accounts/${EXPO_OWNER}/projects/${BUILDER_SLUG}/builds/${urlMatch[1]}` });
        reject(new Error(`فشل إرسال البناء (exit ${code}):\n${(stderr || stdout).slice(0, 600)}`));
      });

      setTimeout(() => { cmd.kill(); reject(new Error("انتهت مهلة إرسال البناء")); }, 180_000);
    });

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      if (attempt > 0) {
        fixLog.push(`🔄 محاولة ${attempt + 1}/${maxRetries + 1} — إصلاح الكود بـ AI...`);
        const review = await aiReviewAndFix(currentCode, lastError);
        currentCode = review.fixedCode;
        fixLog.push(`🧠 AI#1 (${review.modelUsed}): ${review.issues.filter(i => !i.startsWith("[تدقيق]")).length} مشكلة`);
        fixLog.push(`🔍 AI#2 (${review.validatorModel}): ${review.issues.filter(i => i.startsWith("[تدقيق]")).length} مشكلة إضافية`);
        for (const issue of review.issues) fixLog.push(`  🔧 ${issue}`);

        // Update App.tsx and re-commit (NO re-running lockfile/yarn)
        fs.writeFileSync(path.join(projectDir, "App.tsx"), currentCode);
        gitCommitUpdate(projectDir, `ai-fix-attempt-${attempt}`);
      }

      const result = await runBuild();
      return { ...result, retries: attempt, fixLog };
    } catch (err: any) {
      lastError = err.message || String(err);
      fixLog.push(`❌ فشل المحاولة ${attempt + 1}: ${lastError.substring(0, 200)}`);
      if (attempt === maxRetries) {
        throw new Error(`فشل البناء بعد ${maxRetries + 1} محاولات:\n${fixLog.join("\n")}`);
      }
    }
  }

  throw new Error("فشل غير متوقع");
}

// ════════════════════════════════════════════════════════════════
// Desktop App Builder — Electron project generator
// ════════════════════════════════════════════════════════════════

export async function createElectronProject(
  appName: string,
  appCode: string,
  iconUrl?: string,
): Promise<{ projectDir: string; slug: string }> {
  const uid = crypto.randomBytes(4).toString("hex");
  const slug = `hayo-desktop-${slugify(appName)}-${uid}`;
  const projectDir = path.join(BUILD_DIR_ROOT, slug);

  fs.mkdirSync(path.join(projectDir, "src"),    { recursive: true });
  fs.mkdirSync(path.join(projectDir, "assets"), { recursive: true });

  if (iconUrl) {
    try {
      const res = await fetch(iconUrl, { signal: AbortSignal.timeout(15000) });
      if (res.ok) fs.writeFileSync(path.join(projectDir, "assets", "icon.png"), Buffer.from(await res.arrayBuffer()));
    } catch {}
  }

  fs.writeFileSync(path.join(projectDir, "package.json"), JSON.stringify({
    name: slug, version: "1.0.0", main: "main.js",
    scripts: { start: "electron .", build: "electron-builder --win --x64", "build:linux": "electron-builder --linux", "build:mac": "electron-builder --mac" },
    dependencies: { electron: "^28.0.0" },
    devDependencies: { "electron-builder": "^24.0.0" },
    build: {
      appId: `com.hayo.${slug.replace(/-/g, "")}`,
      productName: appName,
      directories: { output: "dist" },
      win: { target: "nsis", icon: "assets/icon.png" },
      linux: { target: "AppImage" },
      mac: { target: "dmg" },
    },
  }, null, 2));

  fs.writeFileSync(path.join(projectDir, "main.js"), `const { app, BrowserWindow } = require('electron');
const path = require('path');
function createWindow() {
  const win = new BrowserWindow({
    width: 1200, height: 800,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
    icon: path.join(__dirname, 'assets', 'icon.png'),
  });
  win.loadFile('src/index.html');
}
app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
`);

  fs.writeFileSync(path.join(projectDir, "src", "index.html"), `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${appName}</title>
  <style>* { margin:0; padding:0; box-sizing:border-box; } body { font-family:'Segoe UI',system-ui,sans-serif; background:#0a0a0f; color:#fff; }</style>
</head>
<body><div id="root"></div><script src="app.js"></script></body>
</html>`);

  fs.writeFileSync(path.join(projectDir, "src", "app.js"), appCode);

  return { projectDir, slug };
}

// ── Build Windows EXE using electron-packager ────────────────────
const DESKTOP_BUILD_DIR = path.join(os.tmpdir(), "hayo-desktop-builds");
const ELECTRON_CACHE    = path.join(os.tmpdir(), "electron-cache");

export async function buildWindowsApp(
  appName: string,
  appCode: string,
  buildId: number,
  iconBase64?: string,
): Promise<{ zipPath: string; filename: string }> {
  const uid = crypto.randomBytes(4).toString("hex");
  const slug = `hayo-${slugify(appName)}-${uid}`;
  const buildDir = path.join(DESKTOP_BUILD_DIR, String(buildId));
  const projectDir = path.join(buildDir, "project");
  const outputDir  = path.join(buildDir, "output");

  fs.mkdirSync(projectDir, { recursive: true });
  fs.mkdirSync(outputDir,  { recursive: true });
  fs.mkdirSync(ELECTRON_CACHE, { recursive: true });

  // Write package.json
  fs.writeFileSync(path.join(projectDir, "package.json"), JSON.stringify({
    name: slug, version: "1.0.0", main: "main.js",
    description: appName,
  }, null, 2));

  // Write main.js
  fs.writeFileSync(path.join(projectDir, "main.js"), `const { app, BrowserWindow } = require('electron');
const path = require('path');
function createWindow() {
  const win = new BrowserWindow({
    width: 1200, height: 800, title: '${appName.replace(/'/g, "\\'")}',
    webPreferences: { nodeIntegration: true, contextIsolation: false },
  });
  win.loadFile('src/index.html');
  win.setMenuBarVisibility(false);
}
app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
`);

  // Write HTML wrapper
  fs.mkdirSync(path.join(projectDir, "src"), { recursive: true });
  fs.writeFileSync(path.join(projectDir, "src", "index.html"), `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${appName}</title>
  <style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a0f;color:#fff;overflow-x:hidden;}</style>
</head>
<body><div id="root"></div><script src="app.js"></script></body>
</html>`);
  fs.writeFileSync(path.join(projectDir, "src", "app.js"), appCode);

  // Write icon if provided
  let iconPath: string | undefined;
  if (iconBase64) {
    try {
      const iconBuf = Buffer.from(iconBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");
      iconPath = path.join(projectDir, "icon.png");
      fs.writeFileSync(iconPath, iconBuf);
    } catch {}
  }

  // Run electron-packager
  console.log(`[Desktop Builder] Packaging Windows app: ${appName} (buildId=${buildId})`);
  // Resolve electron-packager binary path from npm global root
  const npmGlobalRoot = execSync("npm root -g 2>/dev/null || echo /usr/lib/node_modules", { stdio: "pipe" }).toString().trim();
  // npm root -g → /home/runner/.../.config/npm/node_global/lib/node_modules
  // We need → /home/runner/.../.config/npm/node_global/bin/electron-packager
  const packagerBin = npmGlobalRoot.replace(/[\\/]lib[\\/]node_modules$/, "/bin/electron-packager");

  const packagerArgs = [
    ".", appName,
    "--platform=win32", "--arch=x64",
    "--electron-version=28.3.3",
    `--out=${outputDir}`,
    `--download.cacheRoot=${ELECTRON_CACHE}`,
    "--overwrite",
    "--asar",
  ];
  if (iconPath) packagerArgs.push(`--icon=${iconPath}`);

  await new Promise<void>((resolve, reject) => {
    const child = spawn(packagerBin, packagerArgs, {
      cwd: projectDir,
      env: { ...process.env, HOME: process.env.HOME || "/root", PATH: buildEnvPath() },
      stdio: "pipe",
    });
    let stderr = "";
    child.stderr?.on("data", (d: Buffer) => { stderr += d.toString(); });
    child.stdout?.on("data", (d: Buffer) => console.log(`[Desktop Builder] ${d.toString().trim()}`));
    const timeout = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("انتهى وقت البناء (10 دقائق)")); }, 600_000);
    child.on("close", (code: number) => {
      clearTimeout(timeout);
      if (code === 0) resolve();
      else reject(new Error(`electron-packager فشل (exit ${code}): ${stderr.slice(-500)}`));
    });
    child.on("error", (err: Error) => { clearTimeout(timeout); reject(err); });
  });

  // Find the output directory (AppName-win32-x64)
  const outputFolderName = fs.readdirSync(outputDir).find(n => n.endsWith("-win32-x64"));
  if (!outputFolderName) throw new Error("electron-packager لم ينشئ مجلد الإخراج");

  const safeAppName = appName.replace(/[^a-zA-Z0-9\u0600-\u06FF\s_-]/g, "").trim() || "desktop-app";
  const zipFilename = `${safeAppName}-Windows.zip`;
  const zipPath     = path.join(buildDir, zipFilename);

  // ZIP the output folder
  console.log(`[Desktop Builder] Creating ZIP: ${zipPath}`);
  execSync(`zip -r "${zipPath}" "${outputFolderName}"`, {
    cwd: outputDir,
    stdio: "pipe",
    timeout: 120_000,
  });

  // Cleanup project dir to free space (keep output zip)
  try { fs.rmSync(projectDir, { recursive: true, force: true }); } catch {}
  try { fs.rmSync(path.join(outputDir, outputFolderName), { recursive: true, force: true }); } catch {}

  console.log(`[Desktop Builder] ✅ Done: ${zipPath}`);
  return { zipPath, filename: zipFilename };
}

// ── Create Electron Project as in-memory ZIP ─────────────────────
export async function createElectronZip(
  appName: string,
  appCode: string,
  iconBase64?: string,
): Promise<Buffer> {
  const slug = slugify(appName) || "hayo-app";
  const pkg = `com.hayo.${slug.replace(/-/g, "").slice(0, 30)}`;

  const zip = new JSZip();

  zip.file("package.json", JSON.stringify({
    name: slug,
    version: "1.0.0",
    main: "main.js",
    scripts: {
      start: "electron .",
      build: "electron-builder --win --x64",
      "build:linux": "electron-builder --linux",
      "build:mac": "electron-builder --mac",
    },
    dependencies: { electron: "^28.0.0" },
    devDependencies: { "electron-builder": "^24.0.0" },
    build: {
      appId: pkg,
      productName: appName,
      directories: { output: "dist" },
      win: { target: "nsis", icon: "assets/icon.png" },
      linux: { target: "AppImage" },
      mac: { target: "dmg" },
    },
  }, null, 2));

  zip.file("main.js", `const { app, BrowserWindow } = require('electron');
const path = require('path');
function createWindow() {
  const win = new BrowserWindow({
    width: 1200, height: 800,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
    icon: path.join(__dirname, 'assets', 'icon.png'),
  });
  win.loadFile('src/index.html');
}
app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
`);

  zip.file("src/index.html", `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${appName}</title>
  <style>* { margin:0; padding:0; box-sizing:border-box; } body { font-family:'Segoe UI',system-ui,sans-serif; background:#0a0a0f; color:#fff; }</style>
</head>
<body><div id="root"></div><script src="app.js"></script></body>
</html>`);

  zip.file("src/app.js", appCode);

  zip.file("README.md", `# ${appName}

## بناء التطبيق
\`\`\`bash
npm install
npm run build      # Windows EXE
npm run build:linux  # Linux AppImage
npm run build:mac    # macOS DMG
\`\`\`

## تشغيل للتطوير
\`\`\`bash
npm install
npm start
\`\`\`
`);

  if (iconBase64) {
    try {
      const buf = Buffer.from(iconBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");
      zip.file("assets/icon.png", buf);
    } catch {}
  } else {
    zip.folder("assets");
  }

  return zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE", compressionOptions: { level: 6 } });
}

// ── Package an uploaded desktop project ZIP as a clean Electron ZIP ──
export async function packageDesktopUpload(
  zipBase64: string,
  appName: string,
  iconBase64?: string,
): Promise<Buffer> {
  const raw = Buffer.from(zipBase64, "base64");
  const uploaded = await JSZip.loadAsync(raw);

  const outZip = new JSZip();
  const slug = slugify(appName) || "hayo-desktop";
  const pkg = `com.hayo.${slug.replace(/-/g, "").slice(0, 30)}`;

  const fileNames = Object.keys(uploaded.files);

  // Detect root prefix (e.g. "my-app/src/..." → strip "my-app/")
  const firstFile = fileNames.find(n => !uploaded.files[n].dir);
  const firstParts = firstFile ? firstFile.split("/") : [];
  const rootPrefix = firstParts.length > 1 ? firstParts[0] + "/" : "";

  const hasMainJs = fileNames.some(n => n.replace(rootPrefix, "") === "main.js" || n.replace(rootPrefix, "") === "index.js");
  const hasSrcHtml = fileNames.some(n => n.endsWith(".html"));

  // Copy all user files (strip root prefix, put in src/ if no main.js detected)
  for (const fileName of fileNames) {
    const file = uploaded.files[fileName];
    if (file.dir) continue;
    const relPath = fileName.startsWith(rootPrefix) ? fileName.slice(rootPrefix.length) : fileName;
    if (!relPath) continue;
    const content = await file.async("nodebuffer");
    const destPath = hasMainJs ? relPath : `src/${relPath}`;
    outZip.file(destPath, content);
  }

  // Add/overwrite Electron boilerplate
  if (!hasMainJs) {
    outZip.file("main.js", `const { app, BrowserWindow } = require('electron');
const path = require('path');
function createWindow() {
  const win = new BrowserWindow({
    width: 1200, height: 800,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
    icon: path.join(__dirname, 'assets', 'icon.png'),
  });
  win.loadFile('src/index.html');
}
app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
`);
  }

  // Overwrite package.json with proper electron-builder config
  outZip.file("package.json", JSON.stringify({
    name: slug,
    version: "1.0.0",
    main: "main.js",
    scripts: {
      start: "electron .",
      build: "electron-builder --win --x64",
      "build:linux": "electron-builder --linux",
    },
    dependencies: { electron: "^28.0.0" },
    devDependencies: { "electron-builder": "^24.0.0" },
    build: {
      appId: pkg,
      productName: appName,
      directories: { output: "dist" },
      win: { target: "nsis", icon: "assets/icon.png" },
      linux: { target: "AppImage" },
    },
  }, null, 2));

  if (iconBase64) {
    try {
      const buf = Buffer.from(iconBase64.replace(/^data:image\/\w+;base64,/, ""), "base64");
      outZip.file("assets/icon.png", buf);
    } catch {}
  }

  outZip.file("README.md", `# ${appName}

## بناء التطبيق (على Windows)
\`\`\`bash
npm install
npm run build
\`\`\`
الملف الناتج في مجلد dist/
`);

  return outZip.generateAsync({ type: "nodebuffer", compression: "DEFLATE", compressionOptions: { level: 6 } });
}
