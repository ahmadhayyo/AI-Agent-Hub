# دليل نشر HAYO AI على Railway

## الخطوة 1: رفع المشروع على GitHub
```bash
git init
git add .
git commit -m "HAYO AI - Full Project"
git remote add origin https://github.com/YOUR_USERNAME/hayo-ai.git
git push -u origin main
```

## الخطوة 2: إنشاء مشروع على Railway
1. ادخل https://railway.app وسجل بحساب GitHub
2. اضغط "New Project" → "Deploy from GitHub repo"
3. اختر مستودع hayo-ai

## الخطوة 3: إضافة قاعدة بيانات PostgreSQL
1. في مشروع Railway، اضغط "New" → "Database" → "PostgreSQL"
2. Railway يضيف DATABASE_URL تلقائياً

## الخطوة 4: إضافة المتغيرات البيئية
في إعدادات التطبيق → Variables، أضف:

| المتغير | الوصف |
|---------|-------|
| SESSION_SECRET | نص عشوائي طويل لتشفير الجلسات |
| APP_URL | رابط التطبيق من Railway (يُعطى بعد النشر) |
| TELEGRAM_BOT_TOKEN | توكن بوت HAYO_AI_Signals_bot |
| TELEGRAM_BRIDGE_BOT_TOKEN | توكن بوت ALEPPO_CANDLES6_bot |
| TELEGRAM_OWNER_CHAT_ID | 34498339 |
| TWELVE_DATA_API_KEY | المفتاح الأساسي |
| TWELVE_DATA_API_KEYS | كل المفاتيح مفصولة بفواصل |
| GOOGLE_API_KEY3 | مفتاح Gemini |
| OPENAI_API_KEY | مفتاح OpenAI |
| ANTHROPIC_API_KEY | مفتاح Anthropic |
| DEEPSEEK_API_KEY | مفتاح DeepSeek |
| NODE_ENV | production |
| PORT | 8080 |

## الخطوة 5: تحديث APP_URL
بعد أول نشر، انسخ الرابط الذي يعطيك Railway وحدّث APP_URL

## الخطوة 6: تحديث Webhook للبوتات
بعد النشر، البوتات ستسجل webhook تلقائياً على APP_URL الجديد

## ملاحظات مهمة
- Railway يدعم Dockerfile تلقائياً (موجود في المشروع)
- قاعدة البيانات تُنشأ تلقائياً عند أول تشغيل
- حساب المشرف: Fmf0038@gmail.com (سجّل من صفحة التسجيل أولاً)
- تأكد من تحديث APP_URL بعد النشر لأن البوتات تعتمد عليه
