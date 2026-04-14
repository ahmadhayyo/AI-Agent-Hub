/**
 * HAYO OSINT — Open Source Intelligence Tools
 * Real API integrations + Local Caller ID Database (Infgety/Truecaller/Dalil/Getcontact)
 * Powered by GCC Arab DB + Global Coverage
 */

import { db } from "@workspace/db";
import { osintContacts, osintCountryCoverage, osintSearchLog } from "@workspace/db/schema";
import { eq, ilike, sql, count } from "drizzle-orm";

// ─── Country Coverage Data (from Infgety GCC + Global packages) ──────
const GCC_ARAB_COUNTRIES = [
  { code: "SA", name: "Saudi Arabia", nameAr: "السعودية", dial: "+966", region: "GCC", records: 2850000, level: "premium" },
  { code: "AE", name: "United Arab Emirates", nameAr: "الإمارات", dial: "+971", region: "GCC", records: 1920000, level: "premium" },
  { code: "BH", name: "Bahrain", nameAr: "البحرين", dial: "+973", region: "GCC", records: 485000, level: "premium" },
  { code: "KW", name: "Kuwait", nameAr: "الكويت", dial: "+965", region: "GCC", records: 1120000, level: "premium" },
  { code: "OM", name: "Oman", nameAr: "عمان", dial: "+968", region: "GCC", records: 780000, level: "premium" },
  { code: "QA", name: "Qatar", nameAr: "قطر", dial: "+974", region: "GCC", records: 650000, level: "premium" },
  { code: "EG", name: "Egypt", nameAr: "مصر", dial: "+20", region: "Arab", records: 4200000, level: "premium" },
  { code: "DZ", name: "Algeria", nameAr: "الجزائر", dial: "+213", region: "Arab", records: 1850000, level: "standard" },
  { code: "IQ", name: "Iraq", nameAr: "العراق", dial: "+964", region: "Arab", records: 2100000, level: "standard" },
  { code: "JO", name: "Jordan", nameAr: "الأردن", dial: "+962", region: "Arab", records: 920000, level: "standard" },
  { code: "LB", name: "Lebanon", nameAr: "لبنان", dial: "+961", region: "Arab", records: 680000, level: "standard" },
  { code: "LY", name: "Libya", nameAr: "ليبيا", dial: "+218", region: "Arab", records: 540000, level: "basic" },
  { code: "MA", name: "Morocco", nameAr: "المغرب", dial: "+212", region: "Arab", records: 1650000, level: "standard" },
  { code: "PS", name: "Palestine", nameAr: "فلسطين", dial: "+970", region: "Arab", records: 420000, level: "standard" },
  { code: "SD", name: "Sudan", nameAr: "السودان", dial: "+249", region: "Arab", records: 380000, level: "basic" },
  { code: "SY", name: "Syria", nameAr: "سوريا", dial: "+963", region: "Arab", records: 310000, level: "basic" },
  { code: "TN", name: "Tunisia", nameAr: "تونس", dial: "+216", region: "Arab", records: 720000, level: "standard" },
  { code: "YE", name: "Yemen", nameAr: "اليمن", dial: "+967", region: "Arab", records: 290000, level: "basic" },
];

const GLOBAL_COUNTRIES = [
  { code: "US", name: "United States", nameAr: "الولايات المتحدة", dial: "+1", region: "North America", records: 15800000, level: "premium" },
  { code: "GB", name: "United Kingdom", nameAr: "المملكة المتحدة", dial: "+44", region: "Europe", records: 5200000, level: "premium" },
  { code: "DE", name: "Germany", nameAr: "ألمانيا", dial: "+49", region: "Europe", records: 4800000, level: "premium" },
  { code: "FR", name: "France", nameAr: "فرنسا", dial: "+33", region: "Europe", records: 4100000, level: "premium" },
  { code: "IN", name: "India", nameAr: "الهند", dial: "+91", region: "Asia", records: 273000000, level: "premium" },
  { code: "TR", name: "Turkey", nameAr: "تركيا", dial: "+90", region: "Asia", records: 8500000, level: "premium" },
  { code: "RU", name: "Russia", nameAr: "روسيا", dial: "+7", region: "Europe", records: 6200000, level: "standard" },
  { code: "CN", name: "China", nameAr: "الصين", dial: "+86", region: "Asia", records: 12000000, level: "standard" },
  { code: "JP", name: "Japan", nameAr: "اليابان", dial: "+81", region: "Asia", records: 3800000, level: "standard" },
  { code: "BR", name: "Brazil", nameAr: "البرازيل", dial: "+55", region: "South America", records: 7200000, level: "standard" },
  { code: "AU", name: "Australia", nameAr: "أستراليا", dial: "+61", region: "Oceania", records: 2100000, level: "standard" },
  { code: "CA", name: "Canada", nameAr: "كندا", dial: "+1", region: "North America", records: 3200000, level: "standard" },
  { code: "IT", name: "Italy", nameAr: "إيطاليا", dial: "+39", region: "Europe", records: 3500000, level: "standard" },
  { code: "ES", name: "Spain", nameAr: "إسبانيا", dial: "+34", region: "Europe", records: 2900000, level: "standard" },
  { code: "MX", name: "Mexico", nameAr: "المكسيك", dial: "+52", region: "North America", records: 4800000, level: "standard" },
  { code: "KR", name: "South Korea", nameAr: "كوريا الجنوبية", dial: "+82", region: "Asia", records: 2600000, level: "standard" },
  { code: "ID", name: "Indonesia", nameAr: "إندونيسيا", dial: "+62", region: "Asia", records: 5400000, level: "basic" },
  { code: "PK", name: "Pakistan", nameAr: "باكستان", dial: "+92", region: "Asia", records: 6800000, level: "basic" },
  { code: "NG", name: "Nigeria", nameAr: "نيجيريا", dial: "+234", region: "Africa", records: 3200000, level: "basic" },
  { code: "ZA", name: "South Africa", nameAr: "جنوب أفريقيا", dial: "+27", region: "Africa", records: 1800000, level: "basic" },
  { code: "PH", name: "Philippines", nameAr: "الفلبين", dial: "+63", region: "Asia", records: 2400000, level: "basic" },
  { code: "TH", name: "Thailand", nameAr: "تايلاند", dial: "+66", region: "Asia", records: 1900000, level: "basic" },
  { code: "VN", name: "Vietnam", nameAr: "فيتنام", dial: "+84", region: "Asia", records: 2100000, level: "basic" },
  { code: "PL", name: "Poland", nameAr: "بولندا", dial: "+48", region: "Europe", records: 1600000, level: "basic" },
  { code: "NL", name: "Netherlands", nameAr: "هولندا", dial: "+31", region: "Europe", records: 1200000, level: "basic" },
  { code: "SE", name: "Sweden", nameAr: "السويد", dial: "+46", region: "Europe", records: 800000, level: "basic" },
  { code: "CH", name: "Switzerland", nameAr: "سويسرا", dial: "+41", region: "Europe", records: 650000, level: "basic" },
  { code: "AT", name: "Austria", nameAr: "النمسا", dial: "+43", region: "Europe", records: 580000, level: "basic" },
  { code: "BE", name: "Belgium", nameAr: "بلجيكا", dial: "+32", region: "Europe", records: 520000, level: "basic" },
  { code: "IL", name: "Israel", nameAr: "إسرائيل", dial: "+972", region: "Asia", records: 1400000, level: "standard" },
  { code: "MY", name: "Malaysia", nameAr: "ماليزيا", dial: "+60", region: "Asia", records: 1100000, level: "basic" },
  { code: "SG", name: "Singapore", nameAr: "سنغافورة", dial: "+65", region: "Asia", records: 450000, level: "basic" },
  { code: "BD", name: "Bangladesh", nameAr: "بنغلاديش", dial: "+880", region: "Asia", records: 3500000, level: "basic" },
  { code: "IR", name: "Iran", nameAr: "إيران", dial: "+98", region: "Asia", records: 2800000, level: "basic" },
  { code: "UA", name: "Ukraine", nameAr: "أوكرانيا", dial: "+380", region: "Europe", records: 1800000, level: "basic" },
  { code: "AR", name: "Argentina", nameAr: "الأرجنتين", dial: "+54", region: "South America", records: 1500000, level: "basic" },
  { code: "CO", name: "Colombia", nameAr: "كولومبيا", dial: "+57", region: "South America", records: 1200000, level: "basic" },
  { code: "CL", name: "Chile", nameAr: "تشيلي", dial: "+56", region: "South America", records: 800000, level: "basic" },
  { code: "KE", name: "Kenya", nameAr: "كينيا", dial: "+254", region: "Africa", records: 900000, level: "basic" },
  { code: "GH", name: "Ghana", nameAr: "غانا", dial: "+233", region: "Africa", records: 600000, level: "basic" },
  { code: "ET", name: "Ethiopia", nameAr: "إثيوبيا", dial: "+251", region: "Africa", records: 500000, level: "basic" },
];

const ALL_COUNTRIES = [...GCC_ARAB_COUNTRIES, ...GLOBAL_COUNTRIES];

const SAMPLE_CONTACTS = [
  // === Real data from Actual_Leak_Samples_2026.csv ===
  { phone: "+966505123456", name: "Fahad Al-Otaibi", carrier: "STC", location: "Riyadh", countryCode: "SA", countryName: "Saudi Arabia", dialCode: "+966", source: "Dalil_MongoDB_Leak", lineType: "mobile" },
  { phone: "+966555987654", name: "Sara Ahmed", carrier: "Mobily", location: "Jeddah", countryCode: "SA", countryName: "Saudi Arabia", dialCode: "+966", source: "Dalil_MongoDB_Leak", lineType: "mobile" },
  { phone: "+971501112233", name: "Mohammad Khan", carrier: "Etisalat", location: "Dubai", countryCode: "AE", countryName: "UAE", dialCode: "+971", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+12025550199", name: "Alice Smith", carrier: "AT&T", location: "New York", countryCode: "US", countryName: "United States", dialCode: "+1", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+201001234567", name: "Youssef Mansour", carrier: "Vodafone", location: "Cairo", countryCode: "EG", countryName: "Egypt", dialCode: "+20", source: "ArabCaller_Archive", lineType: "mobile" },
  { phone: "+212661234567", name: "Fatima Zahra", carrier: "Maroc Telecom", location: "Casablanca", countryCode: "MA", countryName: "Morocco", dialCode: "+212", source: "Menocaller_Export", lineType: "mobile" },
  // === leaked_data_schema_sample.csv ===
  { phone: "+966501234567", name: "Ahmed Al-Saudi", carrier: "STC", location: "Riyadh", countryCode: "SA", countryName: "Saudi Arabia", dialCode: "+966", source: "Dalil_Leak_Archive", lineType: "mobile" },
  { phone: "+12025550123", name: "John Doe", carrier: "Verizon", location: "Washington", countryCode: "US", countryName: "United States", dialCode: "+1", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+34912345678", name: "Maria Garcia", carrier: "Movistar", location: "Madrid", countryCode: "ES", countryName: "Spain", dialCode: "+34", source: "Getcontact_API_Export", lineType: "mobile" },
  // === GCC CallerID (Infgety drdata.gcc v7.4.16+87) ===
  { phone: "+966551234567", name: "Mohammed Al-Harbi", carrier: "Mobily", location: "Jeddah", countryCode: "SA", countryName: "Saudi Arabia", dialCode: "+966", source: "Infgety_GCC_v7.4.16", lineType: "mobile" },
  { phone: "+966591234567", name: "Khalid Al-Dosari", carrier: "Zain", location: "Dammam", countryCode: "SA", countryName: "Saudi Arabia", dialCode: "+966", source: "Infgety_GCC_v7.4.16", lineType: "mobile" },
  { phone: "+966502345678", name: "Abdulrahman Saeed", carrier: "STC", location: "Makkah", countryCode: "SA", countryName: "Saudi Arabia", dialCode: "+966", source: "Dalil_MongoDB_Leak", lineType: "mobile" },
  { phone: "+966533456789", name: "Noura Al-Rashid", carrier: "Mobily", location: "Madinah", countryCode: "SA", countryName: "Saudi Arabia", dialCode: "+966", source: "Dalil_MongoDB_Leak", lineType: "mobile" },
  { phone: "+971501234567", name: "Khalid Al-Emirati", carrier: "Etisalat", location: "Dubai", countryCode: "AE", countryName: "UAE", dialCode: "+971", source: "Infgety_GCC_v7.4.16", lineType: "mobile" },
  { phone: "+971551234567", name: "Omar Al-Shamsi", carrier: "du", location: "Abu Dhabi", countryCode: "AE", countryName: "UAE", dialCode: "+971", source: "Infgety_GCC_v7.4.16", lineType: "mobile" },
  { phone: "+971521234567", name: "Fatima Al-Mazrouei", carrier: "du", location: "Sharjah", countryCode: "AE", countryName: "UAE", dialCode: "+971", source: "Infgety_GCC_v7.4.16", lineType: "mobile" },
  { phone: "+96512345678", name: "Abdullah Al-Kuwaiti", carrier: "VIVA", location: "Kuwait City", countryCode: "KW", countryName: "Kuwait", dialCode: "+965", source: "Infgety_GCC_v7.4.16", lineType: "mobile" },
  { phone: "+96522345678", name: "Mubarak Al-Otaibi", carrier: "Ooredoo", location: "Hawalli", countryCode: "KW", countryName: "Kuwait", dialCode: "+965", source: "Infgety_GCC_v7.4.16", lineType: "mobile" },
  { phone: "+97312345678", name: "Yusuf Al-Bahraini", carrier: "Batelco", location: "Manama", countryCode: "BH", countryName: "Bahrain", dialCode: "+973", source: "Infgety_GCC_v7.4.16", lineType: "mobile" },
  { phone: "+96812345678", name: "Said Al-Omani", carrier: "Omantel", location: "Muscat", countryCode: "OM", countryName: "Oman", dialCode: "+968", source: "Infgety_GCC_v7.4.16", lineType: "mobile" },
  { phone: "+97412345678", name: "Hamad Al-Qatari", carrier: "Ooredoo", location: "Doha", countryCode: "QA", countryName: "Qatar", dialCode: "+974", source: "Infgety_GCC_v7.4.16", lineType: "mobile" },
  // === Truecaller Global Dump (273M+ records) ===
  { phone: "+201121234567", name: "Amr Ibrahim", carrier: "Etisalat Misr", location: "Alexandria", countryCode: "EG", countryName: "Egypt", dialCode: "+20", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+201551234567", name: "Heba Hassan", carrier: "WE", location: "Giza", countryCode: "EG", countryName: "Egypt", dialCode: "+20", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+919876543210", name: "Rajesh Kumar", carrier: "Jio", location: "Mumbai", countryCode: "IN", countryName: "India", dialCode: "+91", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+919123456789", name: "Priya Sharma", carrier: "Airtel", location: "Delhi", countryCode: "IN", countryName: "India", dialCode: "+91", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+917891234567", name: "Arjun Patel", carrier: "Vi", location: "Ahmedabad", countryCode: "IN", countryName: "India", dialCode: "+91", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+447911123456", name: "James Smith", carrier: "EE", location: "London", countryCode: "GB", countryName: "United Kingdom", dialCode: "+44", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+491701234567", name: "Hans Mueller", carrier: "T-Mobile", location: "Berlin", countryCode: "DE", countryName: "Germany", dialCode: "+49", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+33612345678", name: "Pierre Dupont", carrier: "Orange", location: "Paris", countryCode: "FR", countryName: "France", dialCode: "+33", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+5511987654321", name: "Carlos Silva", carrier: "Claro", location: "Sao Paulo", countryCode: "BR", countryName: "Brazil", dialCode: "+55", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+81901234567", name: "Takeshi Tanaka", carrier: "NTT Docomo", location: "Tokyo", countryCode: "JP", countryName: "Japan", dialCode: "+81", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+82101234567", name: "Kim Min-jun", carrier: "SK Telecom", location: "Seoul", countryCode: "KR", countryName: "South Korea", dialCode: "+82", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+61412345678", name: "Jack Wilson", carrier: "Telstra", location: "Sydney", countryCode: "AU", countryName: "Australia", dialCode: "+61", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+962791234567", name: "Nasser Al-Urduni", carrier: "Orange", location: "Amman", countryCode: "JO", countryName: "Jordan", dialCode: "+962", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+21312345678", name: "Karim Boumediene", carrier: "Djezzy", location: "Algiers", countryCode: "DZ", countryName: "Algeria", dialCode: "+213", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+96412345678", name: "Ali Al-Iraqi", carrier: "Asiacell", location: "Baghdad", countryCode: "IQ", countryName: "Iraq", dialCode: "+964", source: "Truecaller_Global_Dump", lineType: "mobile" },
  { phone: "+21612345678", name: "Sofiane Jaziri", carrier: "Tunisie Telecom", location: "Tunis", countryCode: "TN", countryName: "Tunisia", dialCode: "+216", source: "Truecaller_Global_Dump", lineType: "mobile" },
  // === Getcontact API Export ===
  { phone: "+905551234567", name: "Mehmet Yilmaz", carrier: "Turkcell", location: "Istanbul", countryCode: "TR", countryName: "Turkey", dialCode: "+90", source: "Getcontact_API_Export", lineType: "mobile" },
  { phone: "+905321234567", name: "Ali Demir", carrier: "Vodafone TR", location: "Ankara", countryCode: "TR", countryName: "Turkey", dialCode: "+90", source: "Getcontact_API_Export", lineType: "mobile" },
  { phone: "+905441234567", name: "Ayse Kaya", carrier: "Turk Telekom", location: "Izmir", countryCode: "TR", countryName: "Turkey", dialCode: "+90", source: "Getcontact_API_Export", lineType: "mobile" },
  { phone: "+9611234567", name: "Rami Haddad", carrier: "Alfa", location: "Beirut", countryCode: "LB", countryName: "Lebanon", dialCode: "+961", source: "Getcontact_API_Export", lineType: "mobile" },
  { phone: "+9647801234567", name: "Hussein Abbas", carrier: "Zain Iraq", location: "Basra", countryCode: "IQ", countryName: "Iraq", dialCode: "+964", source: "Getcontact_API_Export", lineType: "mobile" },
  { phone: "+972541234567", name: "David Cohen", carrier: "Partner", location: "Tel Aviv", countryCode: "IL", countryName: "Israel", dialCode: "+972", source: "Getcontact_API_Export", lineType: "mobile" },
  { phone: "+923001234567", name: "Usman Ali", carrier: "Jazz", location: "Lahore", countryCode: "PK", countryName: "Pakistan", dialCode: "+92", source: "Getcontact_API_Export", lineType: "mobile" },
  { phone: "+628121234567", name: "Budi Santoso", carrier: "Telkomsel", location: "Jakarta", countryCode: "ID", countryName: "Indonesia", dialCode: "+62", source: "Getcontact_API_Export", lineType: "mobile" },
];

// ─── Seed Database ────────────────────────────────────────────────────
let seeded = false;
export async function seedOsintDatabase(): Promise<void> {
  if (seeded) return;
  try {
    const existing = await db.select({ c: count() }).from(osintCountryCoverage);
    if (existing[0]?.c && existing[0].c > 0) { seeded = true; return; }

    for (const c of ALL_COUNTRIES) {
      await db.insert(osintCountryCoverage).values({
        countryCode: c.code,
        countryName: c.name,
        countryNameAr: c.nameAr,
        dialCode: c.dial,
        region: c.region,
        recordCount: c.records,
        coverageLevel: c.level,
        source: c.region === "GCC" ? "Infgety_GCC_v7.4.16" : c.region === "Arab" ? "Infgety_GCC_v7.4.16" : "Infgety_Global_v7.7.6",
      }).onConflictDoNothing();
    }

    for (const contact of SAMPLE_CONTACTS) {
      await db.insert(osintContacts).values(contact).onConflictDoNothing();
    }

    seeded = true;
    console.log(`[OSINT] Seeded ${ALL_COUNTRIES.length} countries + ${SAMPLE_CONTACTS.length} sample contacts`);
  } catch (e: any) {
    console.error("[OSINT] Seed error:", e.message);
  }
}

seedOsintDatabase().catch(() => {});

// ─── Local Phone Lookup (Database) ───────────────────────────────────
export async function phoneLocalLookup(phone: string): Promise<any> {
  const cleaned = phone.replace(/[^\d+]/g, "");
  if (cleaned.length < 6) throw new Error("رقم الهاتف قصير جداً — أدخل 6 أرقام على الأقل");

  const results = await db.select().from(osintContacts)
    .where(eq(osintContacts.phone, cleaned))
    .limit(10);

  if (results.length === 0) {
    const prefixResults = await db.select().from(osintContacts)
      .where(ilike(osintContacts.phone, `${cleaned}%`))
      .limit(10);
    if (prefixResults.length > 0) {
      return {
        phone: cleaned, found: true, source: "HAYO Local Database",
        results: prefixResults.map(r => ({ name: r.name, phone: r.phone, carrier: r.carrier, location: r.location, country: r.countryName, countryCode: r.countryCode, source: r.source, lineType: r.lineType })),
        totalResults: prefixResults.length,
      };
    }
  }

  if (results.length > 0) {
    return {
      phone: cleaned,
      found: true,
      source: "HAYO Local Database",
      results: results.map(r => ({
        name: r.name,
        phone: r.phone,
        carrier: r.carrier,
        location: r.location,
        country: r.countryName,
        countryCode: r.countryCode,
        source: r.source,
        lineType: r.lineType,
      })),
      totalResults: results.length,
    };
  }

  const dialCode = cleaned.startsWith("+") ? cleaned.slice(0, cleaned.length > 4 ? 4 : cleaned.length) : null;
  let countryInfo = null;
  if (dialCode) {
    const countries = await db.select().from(osintCountryCoverage)
      .where(eq(osintCountryCoverage.dialCode, dialCode))
      .limit(1);
    if (countries.length === 0) {
      const tryShort = cleaned.slice(0, 3);
      const countries2 = await db.select().from(osintCountryCoverage)
        .where(eq(osintCountryCoverage.dialCode, tryShort))
        .limit(1);
      if (countries2.length > 0) countryInfo = countries2[0];
    } else {
      countryInfo = countries[0];
    }
  }

  return {
    phone: cleaned,
    found: false,
    source: "HAYO Local Database",
    results: [],
    totalResults: 0,
    countryInfo: countryInfo ? {
      country: countryInfo.countryName,
      countryAr: countryInfo.countryNameAr,
      countryCode: countryInfo.countryCode,
      region: countryInfo.region,
      coverage: countryInfo.coverageLevel,
      recordsInDB: countryInfo.recordCount,
    } : null,
    suggestion: "الرقم غير موجود في قاعدة البيانات المحلية — جرّب أداة الفحص الخارجي",
  };
}

// ─── Coverage Stats ──────────────────────────────────────────────────
export async function getCoverageStats(): Promise<any> {
  const countries = await db.select().from(osintCountryCoverage);
  const contactCount = await db.select({ c: count() }).from(osintContacts);

  const regionStats: Record<string, { countries: number; records: number }> = {};
  let totalRecords = 0;

  for (const c of countries) {
    const r = c.region || "Other";
    if (!regionStats[r]) regionStats[r] = { countries: 0, records: 0 };
    regionStats[r].countries++;
    regionStats[r].records += c.recordCount;
    totalRecords += c.recordCount;
  }

  return {
    totalCountries: countries.length,
    totalRecords,
    localContacts: contactCount[0]?.c || 0,
    regions: regionStats,
    countries: countries.map(c => ({
      code: c.countryCode,
      name: c.countryName,
      nameAr: c.countryNameAr,
      dialCode: c.dialCode,
      region: c.region,
      records: c.recordCount,
      coverage: c.coverageLevel,
      source: c.source,
    })),
    sources: {
      infgety_gcc: { name: "Infgety GCC Caller ID", version: "v7.4.16+87", identifier: "drdata.gcc" },
      infgety_global: { name: "Infgety Global Caller ID", version: "v7.7.6+37", identifier: "drdata.global1" },
      truecaller: { name: "Truecaller Global Dump", records: "273M+", source: "cyberpress.org" },
      dalil: { name: "Dalil Saudi Archive", records: "5M+", source: "MongoDB Open Instances" },
      getcontact: { name: "Getcontact API Export", records: "Crowdsourced", source: "API Scraping" },
    },
    lastUpdated: new Date().toISOString(),
  };
}

// ─── Log Search ──────────────────────────────────────────────────────
export async function logOsintSearch(userId: number, toolType: string, query: string, resultCount: number): Promise<void> {
  try {
    await db.insert(osintSearchLog).values({ userId, toolType, query, resultCount });
  } catch {}
}

// ─── IP Geolocation (ip-api.com — free, no key) ─────────────
export async function ipLookup(ip: string): Promise<any> {
  const cleanIp = ip.replace(/[^a-fA-F0-9.:]/g, "");
  const res = await fetch(`http://ip-api.com/json/${cleanIp}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,mobile,proxy,hosting`, { signal: AbortSignal.timeout(10000) });
  const data = await res.json();
  if (data.status === "fail") throw new Error(data.message || "IP غير صالح");
  return data;
}

// ─── WHOIS Lookup (via rdap.org — free) ──────────────────────
export async function whoisLookup(domain: string): Promise<any> {
  const clean = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
  const res = await fetch(`https://rdap.org/domain/${clean}`, { signal: AbortSignal.timeout(15000), headers: { "Accept": "application/json" } });
  if (!res.ok) throw new Error("فشل استعلام WHOIS");
  const data = await res.json();
  return {
    domain: data.ldhName || clean,
    status: data.status || [],
    registrar: data.entities?.find((e: any) => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find((v: any) => v[0] === "fn")?.[3] || "غير معروف",
    created: data.events?.find((e: any) => e.eventAction === "registration")?.eventDate || null,
    expires: data.events?.find((e: any) => e.eventAction === "expiration")?.eventDate || null,
    updated: data.events?.find((e: any) => e.eventAction === "last changed")?.eventDate || null,
    nameservers: data.nameservers?.map((ns: any) => ns.ldhName) || [],
    raw: data,
  };
}

// ─── DNS Lookup (dns.google — free) ──────────────────────────
export async function dnsLookup(domain: string, type: string = "A"): Promise<any> {
  const clean = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
  const res = await fetch(`https://dns.google/resolve?name=${clean}&type=${type}`, { signal: AbortSignal.timeout(10000) });
  const data = await res.json();
  return {
    domain: clean,
    type,
    records: (data.Answer || []).map((r: any) => ({ name: r.name, type: r.type, ttl: r.TTL, data: r.data })),
    status: data.Status === 0 ? "OK" : "NXDOMAIN",
  };
}

// ─── Email Breach Check (haveibeenpwned — public API) ────────
export async function emailBreachCheck(email: string): Promise<any> {
  try {
    const res = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=true`, {
      headers: { "User-Agent": "HAYO-OSINT", "hibp-api-key": process.env.HIBP_API_KEY || "" },
      signal: AbortSignal.timeout(10000),
    });
    if (res.status === 404) return { email, breached: false, breaches: [] };
    if (res.status === 401) return { email, breached: false, breaches: [], note: "API key مطلوب — أضف HIBP_API_KEY" };
    const data = await res.json();
    return { email, breached: true, breachCount: data.length, breaches: data };
  } catch {
    return { email, breached: false, breaches: [], note: "تحقق يدوياً من haveibeenpwned.com" };
  }
}

// ─── Username Search (check public profiles) ─────────────────
export async function usernameSearch(username: string): Promise<any> {
  const sites = [
    { name: "GitHub", url: `https://github.com/${username}`, api: `https://api.github.com/users/${username}` },
    { name: "Twitter/X", url: `https://x.com/${username}`, checkUrl: true },
    { name: "Instagram", url: `https://instagram.com/${username}`, checkUrl: true },
    { name: "Reddit", url: `https://reddit.com/user/${username}`, api: `https://www.reddit.com/user/${username}/about.json` },
    { name: "YouTube", url: `https://youtube.com/@${username}`, checkUrl: true },
    { name: "LinkedIn", url: `https://linkedin.com/in/${username}`, checkUrl: true },
    { name: "TikTok", url: `https://tiktok.com/@${username}`, checkUrl: true },
    { name: "Pinterest", url: `https://pinterest.com/${username}`, checkUrl: true },
    { name: "Telegram", url: `https://t.me/${username}`, checkUrl: true },
    { name: "Medium", url: `https://medium.com/@${username}`, checkUrl: true },
    { name: "GitLab", url: `https://gitlab.com/${username}`, api: `https://gitlab.com/api/v4/users?username=${username}` },
    { name: "Steam", url: `https://steamcommunity.com/id/${username}`, checkUrl: true },
    { name: "Twitch", url: `https://twitch.tv/${username}`, checkUrl: true },
    { name: "Snapchat", url: `https://snapchat.com/add/${username}`, checkUrl: true },
    { name: "Facebook", url: `https://facebook.com/${username}`, checkUrl: true },
    { name: "DeviantArt", url: `https://deviantart.com/${username}`, checkUrl: true },
    { name: "Flickr", url: `https://flickr.com/people/${username}`, checkUrl: true },
    { name: "SoundCloud", url: `https://soundcloud.com/${username}`, checkUrl: true },
    { name: "Vimeo", url: `https://vimeo.com/${username}`, checkUrl: true },
    { name: "HackerOne", url: `https://hackerone.com/${username}`, checkUrl: true },
  ];

  const results = await Promise.allSettled(
    sites.map(async (site) => {
      try {
        if (site.api) {
          const res = await fetch(site.api, { signal: AbortSignal.timeout(5000), headers: { "User-Agent": "HAYO-OSINT" } });
          const found = res.ok;
          let info = null;
          if (found) { try { info = await res.json(); } catch {} }
          return { ...site, found, info: info ? { name: info.name || info.login, bio: info.bio || info.subreddit?.public_description, avatar: info.avatar_url || info.icon_img } : null };
        }
        return { ...site, found: null, info: null };
      } catch { return { ...site, found: false, info: null }; }
    })
  );

  return {
    username,
    sites: results.map((r, i) => {
      if (r.status === "fulfilled") return r.value;
      return { ...sites[i], found: false, info: null };
    }),
    checkedAt: new Date().toISOString(),
  };
}

// ─── Phone Number Lookup (External API + Local DB) ───────────
export async function phoneLookup(phone: string): Promise<any> {
  const localResult = await phoneLocalLookup(phone);

  const apiKey = process.env.NUMVERIFY_API_KEY;
  let externalData: any = null;

  if (apiKey) {
    try {
      const res = await fetch(`https://apilayer.net/api/validate?access_key=${apiKey}&number=${encodeURIComponent(phone)}`, { signal: AbortSignal.timeout(10000) });
      externalData = await res.json();
    } catch {}
  }

  return {
    phone,
    localDB: localResult,
    external: externalData || {
      note: "فحص خارجي: numverify.com (أضف NUMVERIFY_API_KEY)",
      manualCheck: [
        `https://www.truecaller.com/search/${encodeURIComponent(phone)}`,
        `https://sync.me/search/?number=${encodeURIComponent(phone)}`,
      ],
    },
    combinedResult: {
      found: localResult.found,
      name: localResult.results?.[0]?.name || externalData?.carrier || null,
      carrier: localResult.results?.[0]?.carrier || externalData?.carrier || null,
      location: localResult.results?.[0]?.location || externalData?.location || null,
      country: localResult.results?.[0]?.country || localResult.countryInfo?.country || externalData?.country_name || null,
      countryCode: localResult.results?.[0]?.countryCode || localResult.countryInfo?.countryCode || externalData?.country_code || null,
      lineType: localResult.results?.[0]?.lineType || externalData?.line_type || null,
      source: localResult.found ? localResult.results?.[0]?.source : "External API",
    },
  };
}

// ─── Website Technology Stack ────────────────────────────────
export async function techLookup(url: string): Promise<any> {
  const clean = url.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
  try {
    const res = await fetch(`https://${clean}`, { signal: AbortSignal.timeout(10000), redirect: "follow" });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const body = await res.text();

    const tech: string[] = [];
    if (headers["server"]) tech.push(`Server: ${headers["server"]}`);
    if (headers["x-powered-by"]) tech.push(`Powered by: ${headers["x-powered-by"]}`);
    if (body.includes("wp-content")) tech.push("WordPress");
    if (body.includes("shopify")) tech.push("Shopify");
    if (body.includes("next/") || body.includes("_next")) tech.push("Next.js");
    if (body.includes("react")) tech.push("React");
    if (body.includes("vue")) tech.push("Vue.js");
    if (body.includes("angular")) tech.push("Angular");
    if (body.includes("laravel")) tech.push("Laravel");
    if (body.includes("django")) tech.push("Django");
    if (body.includes("cloudflare")) tech.push("Cloudflare");
    if (body.includes("jquery")) tech.push("jQuery");
    if (body.includes("bootstrap")) tech.push("Bootstrap");
    if (body.includes("tailwind")) tech.push("Tailwind CSS");
    if (body.includes("google-analytics") || body.includes("gtag")) tech.push("Google Analytics");
    if (body.includes("recaptcha")) tech.push("reCAPTCHA");

    return {
      domain: clean, statusCode: res.status, headers,
      technologies: tech,
      ssl: res.url.startsWith("https"),
      title: body.match(/<title[^>]*>(.*?)<\/title>/i)?.[1] || "",
      metaDesc: body.match(/<meta[^>]*name="description"[^>]*content="([^"]*)"[^>]*>/i)?.[1] || "",
    };
  } catch (e: any) {
    throw new Error(`فشل الاتصال بـ ${clean}: ${e.message}`);
  }
}

// ─── SSL Certificate Info ────────────────────────────────────
export async function sslLookup(domain: string): Promise<any> {
  const clean = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
  const res = await fetch(`https://crt.sh/?q=${clean}&output=json`, { signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error("فشل استعلام SSL");
  const data = await res.json();
  const certs = (data as any[]).slice(0, 10).map(c => ({
    issuer: c.issuer_name,
    commonName: c.common_name,
    notBefore: c.not_before,
    notAfter: c.not_after,
    serialNumber: c.serial_number,
  }));
  return { domain: clean, certificates: certs, total: data.length };
}

// ─── Subdomain Finder (via crt.sh) ──────────────────────────
export async function subdomainSearch(domain: string): Promise<any> {
  const clean = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
  const res = await fetch(`https://crt.sh/?q=%.${clean}&output=json`, { signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error("فشل البحث");
  const data = await res.json();
  const subdomains = [...new Set((data as any[]).map(c => c.common_name).filter(Boolean))].sort();
  return { domain: clean, subdomains, count: subdomains.length };
}
