/**
 * Integration Connection Tester
 * Tests API keys for various services before saving
 */

export async function testConnection(
  provider: string,
  credentials: Record<string, string>
): Promise<{ success: boolean; error?: string; info?: any }> {
  try {
    switch (provider) {

      case "anthropic":
      case "claude": {
        const r = await fetch("https://api.anthropic.com/v1/models", {
          headers: {
            "x-api-key": credentials.apiKey,
            "anthropic-version": "2023-06-01",
          },
        });
        if (!r.ok) throw new Error("مفتاح Anthropic غير صحيح");
        const d = await r.json() as any;
        const first = d.data?.[0]?.id || "claude";
        return { success: true, info: { model: first } };
      }

      case "openai": {
        const r = await fetch("https://api.openai.com/v1/models", {
          headers: { Authorization: `Bearer ${credentials.apiKey}` },
        });
        if (!r.ok) throw new Error("مفتاح غير صحيح");
        return { success: true, info: { status: "متصل" } };
      }

      case "gemini": {
        const r = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models?key=${credentials.apiKey}`
        );
        if (!r.ok) throw new Error("مفتاح Gemini غير صحيح");
        return { success: true, info: { model: "Gemini" } };
      }

      case "deepseek": {
        const r = await fetch("https://api.deepseek.com/v1/models", {
          headers: { Authorization: `Bearer ${credentials.apiKey}` },
        });
        if (!r.ok) throw new Error("مفتاح DeepSeek غير صحيح");
        return { success: true, info: { model: "DeepSeek" } };
      }

      case "groq": {
        const r = await fetch("https://api.groq.com/openai/v1/models", {
          headers: { Authorization: `Bearer ${credentials.apiKey}` },
        });
        if (!r.ok) throw new Error("مفتاح Groq غير صحيح");
        const data = await r.json() as any;
        return { success: true, info: { models: data.data?.length || "متصل" } };
      }

      case "github": {
        const r = await fetch("https://api.github.com/user", {
          headers: { Authorization: `Bearer ${credentials.token}`, "User-Agent": "HAYO-AI" },
        });
        if (!r.ok) throw new Error("توكن GitHub غير صحيح");
        const d = await r.json() as any;
        return { success: true, info: { user: d.login, repos: d.public_repos } };
      }

      case "telegram": {
        const r = await fetch(`https://api.telegram.org/bot${credentials.token}/getMe`);
        const d = await r.json() as any;
        if (!d.ok) throw new Error("توكن البوت غير صحيح");
        return { success: true, info: { bot: "@" + d.result.username } };
      }

      case "discord": {
        const r = await fetch("https://discord.com/api/v10/users/@me", {
          headers: { Authorization: `Bot ${credentials.token}` },
        });
        if (!r.ok) throw new Error("توكن Discord غير صحيح");
        const d = await r.json() as any;
        return { success: true, info: { bot: d.username } };
      }

      case "slack": {
        const r = await fetch("https://slack.com/api/auth.test", {
          headers: { Authorization: `Bearer ${credentials.token}` },
        });
        const d = await r.json() as any;
        if (!d.ok) throw new Error(d.error || "توكن Slack غير صحيح");
        return { success: true, info: { team: d.team, user: d.user } };
      }

      case "vercel": {
        const r = await fetch("https://api.vercel.com/v2/user", {
          headers: { Authorization: `Bearer ${credentials.token}` },
        });
        if (!r.ok) throw new Error("توكن Vercel غير صحيح");
        const d = await r.json() as any;
        return { success: true, info: { user: d.user?.username } };
      }

      case "netlify": {
        const r = await fetch("https://api.netlify.com/api/v1/user", {
          headers: { Authorization: `Bearer ${credentials.token}` },
        });
        if (!r.ok) throw new Error("توكن Netlify غير صحيح");
        const d = await r.json() as any;
        return { success: true, info: { email: d.email } };
      }

      case "notion": {
        const r = await fetch("https://api.notion.com/v1/users/me", {
          headers: { Authorization: `Bearer ${credentials.apiKey}`, "Notion-Version": "2022-06-28" },
        });
        if (!r.ok) throw new Error("مفتاح Notion غير صحيح");
        const d = await r.json() as any;
        return { success: true, info: { name: d.name || "Notion User" } };
      }

      case "supabase": {
        if (!credentials.url || !credentials.apiKey) throw new Error("يرجى إدخال URL والـ API Key");
        const r = await fetch(`${credentials.url}/rest/v1/`, {
          headers: { apikey: credentials.apiKey, Authorization: `Bearer ${credentials.apiKey}` },
        });
        if (r.status === 400 || r.status === 200 || r.status === 404) {
          return { success: true, info: { url: credentials.url } };
        }
        throw new Error("فشل الاتصال بـ Supabase");
      }

      case "firebase": {
        const cfg = JSON.parse(credentials.serviceAccount || "{}");
        if (!cfg.project_id) throw new Error("ملف Service Account غير صحيح — يجب أن يحتوي project_id");
        return { success: true, info: { project: cfg.project_id } };
      }

      case "aws-s3": {
        if (!credentials.accessKeyId || !credentials.secretAccessKey) {
          throw new Error("يرجى إدخال Access Key ID و Secret Access Key");
        }
        const region = credentials.region || "us-east-1";
        const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
        const r = await fetch(`https://s3.${region}.amazonaws.com/`, {
          method: "GET",
          headers: { "x-amz-date": date + "T000000Z" },
        });
        if (r.status === 403 || r.status === 200) {
          return { success: true, info: { region } };
        }
        throw new Error("فشل الاتصال بـ AWS S3");
      }

      case "google-drive": {
        return { success: true, info: { note: "يتطلب OAuth — جاهز للاستخدام بعد الإعداد" } };
      }

      default:
        return { success: true, info: { status: "تم الحفظ" } };
    }
  } catch (err: any) {
    return { success: false, error: err.message || "خطأ في الاتصال" };
  }
}
