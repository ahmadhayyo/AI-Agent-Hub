# دليل نشر HAYO AI على Railway (جاهز إنتاجياً)

هذا الدليل محدث لهيكل المشروع الحالي (monorepo + pnpm workspaces) مع:
- `Dockerfile` محسّن للإنتاج
- `railway.json` لضبط start command
- `nixpacks.toml` كخيار بديل
- سكربت تشغيل موحد: `scripts/start-railway.sh`

---

## 1) رفع الكود إلى GitHub
```bash
git add .
git commit -m "Prepare Railway deployment"
git push
```

---

## 2) إنشاء مشروع Railway وربطه بالمستودع
1. ادخل https://railway.app
2. New Project → Deploy from GitHub Repo
3. اختر نفس مستودع HAYO AI

> Railway سيكتشف `Dockerfile` تلقائياً ويستخدمه للبناء.

---

## 3) إضافة PostgreSQL
1. داخل Railway Project: New → Database → PostgreSQL
2. سيُضاف `DATABASE_URL` تلقائياً

---

## 4) إعداد المتغيرات البيئية (Variables)

### متغيرات أساسية (إلزامية)
| المتغير | الوصف |
|---|---|
| `DATABASE_URL` | رابط PostgreSQL (يضاف غالباً تلقائياً) |
| `SESSION_SECRET` | نص عشوائي قوي للجلسات |
| `APP_URL` | رابط الخدمة النهائي على Railway |
| `NODE_ENV` | `production` |
| `PORT` | يضبطه Railway تلقائياً (لا تضع قيمة ثابتة إلا للضرورة) |

### متغيرات الذكاء الاصطناعي (بحسب ما تستخدم)
| المتغير |
|---|
| `ANTHROPIC_API_KEY` |
| `OPENAI_API_KEY` |
| `GOOGLE_API_KEY3` |
| `DEEPSEEK_API_KEY` |

### متغيرات Telegram (اختياري لكن موصى به)
| المتغير |
|---|
| `TELEGRAM_BOT_TOKEN` |
| `TELEGRAM_BRIDGE_BOT_TOKEN` |
| `TELEGRAM_OWNER_CHAT_ID` |

### متغيرات السوق (اختياري حسب الميزات)
| المتغير |
|---|
| `TWELVE_DATA_API_KEY` |
| `TWELVE_DATA_API_KEYS` |

---

## 5) أول تشغيل والتحقق
بعد أول Deploy:
1. افتح Logs وتأكد من وصول السيرفر إلى `Server listening`
2. افحص الصحة:
   - `GET /healthz`
3. افتح الواجهة من رابط Railway وتحقق من تسجيل الدخول

---

## 6) تحديث APP_URL النهائي
بعد إنشاء الدومين النهائي على Railway:
- حدّث `APP_URL` بنفس الرابط
- أعد Deploy

هذا ضروري خاصة لو كنت تستخدم Telegram Webhooks.

---

## 7) ملاحظات تشغيلية مهمة
- السيرفر يقرأ `PORT` من Railway مباشرة.
- البناء والتشغيل يتمان عبر:
  - Build: `pnpm --filter @workspace/hayo-ai build && pnpm --filter @workspace/api-server build`
  - Start: `scripts/start-railway.sh`
- سكربت التشغيل ينسخ frontend static build إلى مكان يخدمه backend أثناء التشغيل.

---

## 8) Troubleshooting سريع
- **Build failed**: تحقق من متغيرات البيئة الضرورية ونسخة lockfile.
- **Blank page**: تأكد أن frontend تم بناؤه وأن `dist/public` موجود.
- **DB errors**: تأكد من `DATABASE_URL` وصلاحيات قاعدة البيانات.
- **Telegram لا يعمل**: تحقق من `APP_URL` + التوكنات وأن webhooks تشير للرابط الصحيح.
