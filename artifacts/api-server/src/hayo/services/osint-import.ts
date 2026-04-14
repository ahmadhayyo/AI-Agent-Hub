import { db } from "@workspace/db";
import { osintContacts, osintCountryCoverage } from "@workspace/db/schema";
import { sql, count } from "drizzle-orm";
import { parse } from "csv-parse/sync";

let connectors: any = null;
async function getConnectors() {
  if (!connectors) {
    const { ReplitConnectors } = await import("@replit/connectors-sdk");
    connectors = new ReplitConnectors();
  }
  return connectors;
}

let gcsClient: any = null;
async function getGCS() {
  if (!gcsClient) {
    const { Storage } = await import("@google-cloud/storage");
    gcsClient = new Storage();
  }
  return gcsClient;
}

export interface ImportResult {
  source: string;
  totalParsed: number;
  imported: number;
  skipped: number;
  errors: string[];
  timestamp: string;
}

export interface ImportStats {
  totalContacts: number;
  totalCountries: number;
  sources: { source: string; count: number }[];
  lastImport: string | null;
}

interface ContactRow {
  phone: string;
  name: string;
  carrier?: string;
  location?: string;
  countryCode?: string;
  countryName?: string;
  dialCode?: string;
  source?: string;
  lineType?: string;
}

function normalizePhone(phone: string): string {
  return phone.replace(/[^\d+]/g, "");
}

function parseCSVToContacts(csvContent: string, sourceName: string): ContactRow[] {
  const records = parse(csvContent, {
    columns: true,
    skip_empty_lines: true,
    trim: true,
    relax_column_count: true,
  });

  const contacts: ContactRow[] = [];
  for (const row of records) {
    const phone = normalizePhone(
      row.phone || row.Phone || row.phone_number || row.PhoneNumber || row.mobile || row.Mobile || row.number || ""
    );
    if (phone.length < 6) continue;

    const name = row.name || row.Name || row.full_name || row.FullName || row.contact_name || row.display_name || "Unknown";
    contacts.push({
      phone,
      name,
      carrier: row.carrier || row.Carrier || row.operator || row.Operator || row.network || null,
      location: row.location || row.Location || row.city || row.City || row.address || null,
      countryCode: row.country_code || row.CountryCode || row.cc || row.country || null,
      countryName: row.country_name || row.CountryName || row.country || null,
      dialCode: row.dial_code || row.DialCode || row.prefix || null,
      source: sourceName,
      lineType: row.line_type || row.LineType || row.type || "mobile",
    });
  }
  return contacts;
}

async function bulkInsertContacts(contacts: ContactRow[]): Promise<{ imported: number; skipped: number }> {
  let imported = 0;
  let skipped = 0;
  const BATCH_SIZE = 100;

  for (let i = 0; i < contacts.length; i += BATCH_SIZE) {
    const batch = contacts.slice(i, i + BATCH_SIZE);
    const values = batch.map(c => ({
      phone: c.phone,
      name: c.name,
      carrier: c.carrier || null,
      location: c.location || null,
      countryCode: c.countryCode || null,
      countryName: c.countryName || null,
      dialCode: c.dialCode || null,
      source: c.source || "manual_import",
      lineType: c.lineType || "mobile",
    }));

    try {
      const result = await db.insert(osintContacts).values(values).onConflictDoNothing();
      const insertedCount = (result as any).rowCount ?? batch.length;
      imported += insertedCount;
      skipped += batch.length - insertedCount;
    } catch (e: any) {
      for (const v of values) {
        try {
          await db.insert(osintContacts).values(v).onConflictDoNothing();
          imported++;
        } catch {
          skipped++;
        }
      }
    }
  }

  return { imported, skipped };
}

export async function importFromCSVContent(csvContent: string, sourceName: string): Promise<ImportResult> {
  const errors: string[] = [];
  let contacts: ContactRow[] = [];

  try {
    contacts = parseCSVToContacts(csvContent, sourceName);
  } catch (e: any) {
    return {
      source: sourceName, totalParsed: 0, imported: 0, skipped: 0,
      errors: [`فشل تحليل CSV: ${e.message}`], timestamp: new Date().toISOString(),
    };
  }

  if (contacts.length === 0) {
    return {
      source: sourceName, totalParsed: 0, imported: 0, skipped: 0,
      errors: ["لم يتم العثور على بيانات صالحة في الملف"], timestamp: new Date().toISOString(),
    };
  }

  const { imported, skipped } = await bulkInsertContacts(contacts);
  return {
    source: sourceName, totalParsed: contacts.length, imported, skipped,
    errors, timestamp: new Date().toISOString(),
  };
}

export async function importFromObjectStorage(filePath: string, sourceName: string): Promise<ImportResult> {
  try {
    const bucketId = process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID;
    if (!bucketId) throw new Error("Object Storage غير مهيأ");

    const gcs = await getGCS();
    const bucket = gcs.bucket(bucketId);
    const file = bucket.file(filePath);

    const [exists] = await file.exists();
    if (!exists) throw new Error(`الملف غير موجود: ${filePath}`);

    const [content] = await file.download();
    const csvContent = content.toString("utf-8");
    return importFromCSVContent(csvContent, sourceName || `ObjectStorage:${filePath}`);
  } catch (e: any) {
    return {
      source: sourceName || filePath, totalParsed: 0, imported: 0, skipped: 0,
      errors: [`خطأ في القراءة من Object Storage: ${e.message}`], timestamp: new Date().toISOString(),
    };
  }
}

export async function uploadToObjectStorage(buffer: Buffer, filename: string): Promise<string> {
  const bucketId = process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID;
  if (!bucketId) throw new Error("Object Storage غير مهيأ");

  const gcs = await getGCS();
  const bucket = gcs.bucket(bucketId);
  const path = `osint-data/${Date.now()}_${filename}`;
  const file = bucket.file(path);
  await file.save(buffer, { contentType: "text/csv" });
  return path;
}

export async function listObjectStorageFiles(): Promise<{ name: string; size: number; updated: string }[]> {
  const bucketId = process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID;
  if (!bucketId) return [];

  try {
    const gcs = await getGCS();
    const bucket = gcs.bucket(bucketId);
    const [files] = await bucket.getFiles({ prefix: "osint-data/" });
    return files.map((f: any) => ({
      name: f.name,
      size: parseInt(f.metadata.size || "0"),
      updated: f.metadata.updated || "",
    }));
  } catch {
    return [];
  }
}

export async function importFromGoogleDrive(fileId: string, sourceName: string): Promise<ImportResult> {
  try {
    const conn = await getConnectors();

    const metaRes = await conn.proxy("google-drive", `/drive/v3/files/${fileId}?fields=name,mimeType,size`, { method: "GET" });
    const meta = await metaRes.json();

    let csvContent: string;

    if (meta.mimeType === "application/vnd.google-apps.spreadsheet") {
      const exportRes = await conn.proxy("google-drive", `/drive/v3/files/${fileId}/export?mimeType=text/csv`, { method: "GET" });
      csvContent = await exportRes.text();
    } else {
      const downloadRes = await conn.proxy("google-drive", `/drive/v3/files/${fileId}?alt=media`, { method: "GET" });
      csvContent = await downloadRes.text();
    }

    return importFromCSVContent(csvContent, sourceName || `GoogleDrive:${meta.name || fileId}`);
  } catch (e: any) {
    return {
      source: sourceName || fileId, totalParsed: 0, imported: 0, skipped: 0,
      errors: [`خطأ في القراءة من Google Drive: ${e.message}`], timestamp: new Date().toISOString(),
    };
  }
}

export async function listGoogleDriveFiles(query?: string): Promise<any[]> {
  try {
    const conn = await getConnectors();
    const q = query || "mimeType='text/csv' or mimeType='application/vnd.google-apps.spreadsheet' or name contains '.csv'";
    const res = await conn.proxy("google-drive", `/drive/v3/files?q=${encodeURIComponent(q)}&fields=files(id,name,mimeType,size,modifiedTime)&pageSize=50&orderBy=modifiedTime desc`, { method: "GET" });
    const data = await res.json();
    return data.files || [];
  } catch (e: any) {
    return [];
  }
}

export async function importFromSupabase(connectionUrl: string, tableName: string, sourceName: string): Promise<ImportResult> {
  try {
    const pgModule = await import("pg");
    const Pool = pgModule.default?.Pool || pgModule.Pool;
    const pool = new Pool({ connectionString: connectionUrl, ssl: { rejectUnauthorized: false } });

    const result = await pool.query(`SELECT * FROM "${tableName}" LIMIT 50000`);
    await pool.end();

    if (result.rows.length === 0) {
      return {
        source: sourceName, totalParsed: 0, imported: 0, skipped: 0,
        errors: ["لا توجد بيانات في الجدول المحدد"], timestamp: new Date().toISOString(),
      };
    }

    const contacts: ContactRow[] = result.rows.map((row: any) => ({
      phone: normalizePhone(row.phone || row.phone_number || row.mobile || row.number || ""),
      name: row.name || row.full_name || row.display_name || row.contact_name || "Unknown",
      carrier: row.carrier || row.operator || row.network || null,
      location: row.location || row.city || row.address || null,
      countryCode: row.country_code || row.cc || null,
      countryName: row.country_name || row.country || null,
      dialCode: row.dial_code || row.prefix || null,
      source: sourceName || `Supabase:${tableName}`,
      lineType: row.line_type || row.type || "mobile",
    })).filter((c: ContactRow) => c.phone.length >= 6);

    const { imported, skipped } = await bulkInsertContacts(contacts);
    return {
      source: sourceName || `Supabase:${tableName}`, totalParsed: contacts.length,
      imported, skipped, errors: [], timestamp: new Date().toISOString(),
    };
  } catch (e: any) {
    return {
      source: sourceName || tableName, totalParsed: 0, imported: 0, skipped: 0,
      errors: [`خطأ في الاتصال بـ Supabase: ${e.message}`], timestamp: new Date().toISOString(),
    };
  }
}

export async function listSupabaseTables(connectionUrl: string): Promise<string[]> {
  try {
    const pgModule = await import("pg");
    const Pool = pgModule.default?.Pool || pgModule.Pool;
    const pool = new Pool({ connectionString: connectionUrl, ssl: { rejectUnauthorized: false } });
    const result = await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name`);
    await pool.end();
    return result.rows.map((r: any) => r.table_name);
  } catch {
    return [];
  }
}

export async function getImportStats(): Promise<ImportStats> {
  const [contactCount] = await db.select({ c: count() }).from(osintContacts);
  const [countryCount] = await db.select({ c: count() }).from(osintCountryCoverage);

  const sources = await db.execute(sql`
    SELECT source, COUNT(*)::int as count
    FROM osint_contacts
    GROUP BY source
    ORDER BY count DESC
  `);

  return {
    totalContacts: contactCount?.c || 0,
    totalCountries: countryCount?.c || 0,
    sources: (sources.rows || []) as any[],
    lastImport: new Date().toISOString(),
  };
}

export async function clearAllContacts(): Promise<{ deleted: number }> {
  const [before] = await db.select({ c: count() }).from(osintContacts);
  await db.delete(osintContacts);
  return { deleted: before?.c || 0 };
}

export async function deleteContactsBySource(source: string): Promise<{ deleted: number }> {
  const result = await db.execute(sql`DELETE FROM osint_contacts WHERE source = ${source}`);
  return { deleted: (result as any).rowCount || 0 };
}
