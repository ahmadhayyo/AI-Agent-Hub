# HAYO AI — دليل الإعداد على حساب Replit جديد

## 📋 المتطلبات
- حساب Replit (Pro مُستحسن للنشر)
- مفاتيح API (راجع SECRETS_TEMPLATE.env)
- قاعدة بيانات PostgreSQL (Replit توفّرها مجاناً)

---

## 🚀 خطوات الإعداد

### الخطوة 1: رفع المشروع
1. في Replit → **Create Repl** → **Import from GitHub** أو **Upload ZIP**
2. ارفع ملف ZIP هذا
3. Replit سيكتشف تلقائياً أن المشروع يستخدم **PNPM Workspace** و **Node.js 24**

### الخطوة 2: إعداد قاعدة البيانات
1. في Replit → اضغط **Database** في الشريط الجانبي
2. أنشئ **PostgreSQL Database**
3. الـ `DATABASE_URL` ستُضاف تلقائياً في Secrets

### الخطوة 3: إضافة Secrets
1. في Replit → اضغط على أيقونة **🔒 Secrets**
2. أضف كل متغير من `SECRETS_TEMPLATE.env` مع قيمته الصحيحة
3. **المتغيرات الإلزامية لتشغيل النواة:**
   - `DATABASE_URL` (من قاعدة البيانات)
   - `ANTHROPIC_API_KEY` (Claude Opus)
   - `OPENAI_API_KEY` (GPT-4o)
   - `GOOGLE_API_KEY3` (Gemini)
   - `SESSION_SECRET` (أي نص عشوائي طويل)

4. **المتغيرات الاختيارية:**
   - `TELEGRAM_BOT_TOKEN` (بوت التداول)
   - `TELEGRAM_BRIDGE_BOT_TOKEN` (بوت الجسر)
   - `TELEGRAM_OWNER_CHAT_ID=34498339`
   - `EXPO_ACCESS_TOKEN` (منشئ التطبيقات)
   - `TWELVE_DATA_API_KEY` (بيانات الأسواق)
   - `DEEPSEEK_API_KEY`

### الخطوة 4: تشغيل قاعدة البيانات
في Shell الـ Replit اكتب:
```bash
pnpm run db:push
```
هذا سيُنشئ جداول قاعدة البيانات.

### الخطوة 5: تشغيل المشروع
اضغط **Run** أو:
```bash
pnpm install
pnpm --filter @workspace/api-server run dev
```

---

## 🏗️ هيكل المشروع

```
/
├── artifacts/
│   ├── api-server/         # الخادم الرئيسي (Express + tRPC)
│   │   └── src/
│   │       ├── hayo/       # المنطق الأساسي
│   │       │   ├── providers.ts      # مزودو الذكاء الاصطناعي
│   │       │   ├── router.ts         # جميع API endpoints
│   │       │   └── services/         # الخدمات المتخصصة
│   │       └── telegram/
│   │           └── bot.ts            # بوت تيليغرام (Trading + Bridge)
│   │
│   └── hayo-ai/            # الواجهة الأمامية (React + Vite)
│       └── src/
│           └── pages/      # الصفحات (Home, Chat, Trading, Admin...)
│
├── lib/
│   └── db/                 # مخطط قاعدة البيانات (Drizzle ORM)
│
├── SECRETS_TEMPLATE.env    # قالب متغيرات البيئة
└── pnpm-workspace.yaml     # إعداد المكتبات
```

---

## 🤖 النماذج الذكية المتاحة

| النموذج | المزود | المفتاح |
|---------|--------|---------|
| Claude Opus 4.5/4.6 | Anthropic | ANTHROPIC_API_KEY |
| GPT-4o | OpenAI | OPENAI_API_KEY |
| Gemini 2.5 Flash | Google | GOOGLE_API_KEY3 |
| Gemini 2.5 Pro | Google | GOOGLE_API_KEY3 |
| DeepSeek Chat/R1 | DeepSeek | DEEPSEEK_API_KEY |

---

## 🔑 بيانات الدخول

- **لوحة الأدمن**: `/admin` — كلمة المرور: `6088amhA+`
- **Expo Project**: `08fe9f2e-9a59-443f-b658-6cbc5dea9c34` (مالك: ahmet80)

---

## ⚙️ Workflows التلقائية

Replit سيشغّل الـ Workflows التالية تلقائياً:
1. `API Server` — الخادم الخلفي على المنفذ 8080
2. `web` — الواجهة الأمامية على المنفذ المتغير
3. `Component Preview Server` — للـ Mockup Sandbox

---

## 🐛 استكشاف الأخطاء

**مشكلة: قاعدة البيانات لا تتصل**
```bash
pnpm run db:push
```

**مشكلة: npm packages مفقودة**
```bash
pnpm install --frozen-lockfile
```

**مشكلة: TypeScript errors**
هذه أخطاء في type definitions من مشاكل schema قديمة — لا تؤثر على التشغيل.
الخادم يبني بـ esbuild مباشرة.
