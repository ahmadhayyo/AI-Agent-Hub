/**
 * White-Label Branding Configuration
 * All references to Manus, Forge, or third-party infrastructure are abstracted here
 * Users can customize these values via environment variables
 */

export const BRANDING = {
  // Application Identity
  appName: import.meta.env.VITE_APP_TITLE || "HAYO AI",
  appLogo: import.meta.env.VITE_APP_LOGO || "/logo.png",
  appDescription: import.meta.env.VITE_APP_DESCRIPTION || "Advanced AI Code Generation Platform",
  
  // URLs (Generic, no Manus/Forge references)
  apiUrl: import.meta.env.VITE_API_URL || "http://localhost:3000",
  assetsUrl: import.meta.env.VITE_ASSETS_URL || "https://cdn.example.com",
  storageUrl: import.meta.env.VITE_STORAGE_URL || "https://storage.example.com",
  docsUrl: import.meta.env.VITE_DOCS_URL || "https://docs.example.com",
  supportEmail: import.meta.env.VITE_SUPPORT_EMAIL || "support@example.com",
  
  // OAuth (Generic naming)
  authPortalUrl: import.meta.env.VITE_AUTH_PORTAL_URL || import.meta.env.VITE_OAUTH_PORTAL_URL,
  appId: import.meta.env.VITE_APP_ID,
  
  // Features
  enableGitHub: import.meta.env.VITE_ENABLE_GITHUB === "true",
  enableGoogleDrive: import.meta.env.VITE_ENABLE_GOOGLE_DRIVE === "true",
  enableVercelDeploy: import.meta.env.VITE_ENABLE_VERCEL === "true",
  enableVoiceInput: import.meta.env.VITE_ENABLE_VOICE === "true",
  enableMermaidDiagrams: import.meta.env.VITE_ENABLE_MERMAID === "true",
  enableVersionControl: import.meta.env.VITE_ENABLE_VERSION_CONTROL === "true",
  
  // Branding Colors (can be overridden)
  primaryColor: import.meta.env.VITE_PRIMARY_COLOR || "#6366f1",
  accentColor: import.meta.env.VITE_ACCENT_COLOR || "#8b5cf6",
  
  // Analytics (Generic)
  analyticsEnabled: import.meta.env.VITE_ANALYTICS_ENABLED === "true",
  analyticsEndpoint: import.meta.env.VITE_ANALYTICS_ENDPOINT,
  
  // Company Info
  companyName: import.meta.env.VITE_COMPANY_NAME || "Your Company",
  companyUrl: import.meta.env.VITE_COMPANY_URL || "https://example.com",
  privacyUrl: import.meta.env.VITE_PRIVACY_URL || "https://example.com/privacy",
  termsUrl: import.meta.env.VITE_TERMS_URL || "https://example.com/terms",
};

/**
 * Get asset URL (replaces hardcoded Manus/Aliyun CDN URLs)
 */
export function getAssetUrl(path: string): string {
  const baseUrl = BRANDING.assetsUrl.replace(/\/$/, "");
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  return `${baseUrl}${cleanPath}`;
}

/**
 * Get storage URL for uploaded files
 */
export function getStorageUrl(key: string): string {
  const baseUrl = BRANDING.storageUrl.replace(/\/$/, "");
  return `${baseUrl}/${key}`;
}

/**
 * Get API endpoint
 */
export function getApiUrl(endpoint: string): string {
  const baseUrl = BRANDING.apiUrl.replace(/\/$/, "");
  const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  return `${baseUrl}/api${cleanEndpoint}`;
}
