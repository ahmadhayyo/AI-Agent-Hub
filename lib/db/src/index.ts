import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

// 1. الفحص الصارم: إيقاف التطبيق فوراً وبشكل صريح إذا لم يتم العثور على الرابط في Railway
if (!process.env.DATABASE_URL) {
  throw new Error("CRITICAL ERROR: DATABASE_URL is missing in Railway Environment Variables!");
}

// 2. إنشاء مجمع الاتصالات بقاعدة البيانات باستخدام الرابط
export const pool = new Pool({ 
  connectionString: process.env.DATABASE_URL 
});

// 3. تصدير كائن قاعدة البيانات (db) بشكل نهائي، ولن يكون null أبداً بعد الآن
export const db = drizzle(pool, { schema });

// 4. تصدير المخططات (Schemas) لباقي أجزاء المشروع
export * from "./schema";
