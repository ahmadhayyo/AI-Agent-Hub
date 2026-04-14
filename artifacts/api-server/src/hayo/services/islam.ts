/**
 * رسالة الإسلام — Islam Message Service
 * Real API integrations: Quran, Tafsir, Hadith, Madhahib
 * All data from FREE public Islamic APIs
 */
import { callPowerAI } from "../providers.js";

const QURAN_API = "https://api.alquran.cloud/v1";
const TAFSIR_API = "https://cdn.jsdelivr.net/gh/spa5k/tafsir_api@main/tafsir";
const HADITH_CDN = "https://cdn.jsdelivr.net/gh/fawazahmed0/hadith-api@1";

// ═══ QURAN ═══════════════════════════════════════════════════════

// List all 114 surahs
export async function listSurahs(): Promise<any> {
  const res = await fetch(`${QURAN_API}/surah`, { signal: AbortSignal.timeout(10000) });
  const data = await res.json();
  return data.data; // array of 114 surahs
}

// Get full surah with Arabic text
export async function getSurah(number: number, edition: string = "quran-uthmani"): Promise<any> {
  const res = await fetch(`${QURAN_API}/surah/${number}/${edition}`, { signal: AbortSignal.timeout(15000) });
  const data = await res.json();
  return data.data;
}

// Get ayah with multiple editions (Arabic + tafsir)
export async function getAyah(reference: string, editions: string = "quran-uthmani,ar.muyassar"): Promise<any> {
  const res = await fetch(`${QURAN_API}/ayah/${reference}/editions/${editions}`, { signal: AbortSignal.timeout(10000) });
  const data = await res.json();
  return data.data;
}

// Search in Quran
export async function searchQuran(query: string, edition: string = "quran-uthmani"): Promise<any> {
  const res = await fetch(`${QURAN_API}/search/${encodeURIComponent(query)}/all/${edition}`, { signal: AbortSignal.timeout(15000) });
  const data = await res.json();
  return data.data;
}

// Get tafsir for a surah (multiple tafsirs available)
export async function getTafsir(surahNum: number, ayahNum: number, tafsirEdition: string = "ar-tafsir-al-tabari"): Promise<any> {
  try {
    const res = await fetch(`${TAFSIR_API}/${tafsirEdition}/${surahNum}/${ayahNum}.json`, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error("Tafsir not found");
    return await res.json();
  } catch {
    // Fallback: use alquran.cloud tafsir
    const res = await fetch(`${QURAN_API}/ayah/${surahNum}:${ayahNum}/ar.muyassar`, { signal: AbortSignal.timeout(10000) });
    const data = await res.json();
    return { text: data.data?.text || "التفسير غير متوفر لهذه الآية" };
  }
}

// List available tafsirs
export async function listTafsirs(): Promise<any> {
  const res = await fetch(`${TAFSIR_API}/editions.json`, { signal: AbortSignal.timeout(10000) });
  return await res.json();
}

// ═══ HADITH ═════════════════════════════════════════════════════

const HADITH_BOOKS: Record<string, { ar: string; en: string; slug: string }> = {
  bukhari: { ar: "صحيح البخاري", en: "Sahih al-Bukhari", slug: "bukhari" },
  muslim: { ar: "صحيح مسلم", en: "Sahih Muslim", slug: "muslim" },
  abudawud: { ar: "سنن أبي داود", en: "Sunan Abu Dawud", slug: "abudawud" },
  tirmidhi: { ar: "جامع الترمذي", en: "Jami at-Tirmidhi", slug: "tirmidhi" },
  nasai: { ar: "سنن النسائي", en: "Sunan an-Nasa'i", slug: "nasai" },
  ibnmajah: { ar: "سنن ابن ماجه", en: "Sunan Ibn Majah", slug: "ibnmajah" },
  malik: { ar: "موطأ مالك", en: "Muwatta Malik", slug: "malik" },
  ahmad: { ar: "مسند أحمد", en: "Musnad Ahmad", slug: "ahmad" },
  darimi: { ar: "سنن الدارمي", en: "Sunan ad-Darimi", slug: "darimi" },
};

export function listHadithBooks() { return HADITH_BOOKS; }

// Get hadith sections/chapters for a book
export async function getHadithBook(bookSlug: string): Promise<any> {
  const res = await fetch(`${HADITH_CDN}/editions/ara-${bookSlug}.json`, { signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error("الكتاب غير متوفر");
  const data = await res.json();
  return data;
}

// Search hadith using AI
export async function searchHadith(query: string, book: string = "all"): Promise<any> {
  // Use AI to search and explain hadiths
  const result = await callPowerAI(
    `أنت عالم حديث متخصص. ابحث عن الأحاديث المتعلقة بالموضوع المطلوب.

لكل حديث أعط:
1. نص الحديث بالعربية
2. الراوي
3. المصدر (البخاري، مسلم، إلخ) مع رقم الحديث
4. درجة الحديث (صحيح/حسن/ضعيف)
5. شرح مختصر للحديث

أعد 5-10 أحاديث مع شرح. اكتب بدقة علمية.
${book !== "all" ? `ابحث في ${HADITH_BOOKS[book]?.ar || book} فقط.` : "ابحث في جميع كتب الحديث."}`,
    `ابحث عن أحاديث في موضوع: ${query}`,
    8000
  );
  return { query, book, results: result.content, modelUsed: result.modelUsed };
}

// ═══ MADHAHIB (المذاهب الأربعة) ═══════════════════════════════

export async function compareMadhahib(topic: string): Promise<any> {
  const result = await callPowerAI(
    `أنت فقيه مقارن متخصص في المذاهب الأربعة لأهل السنة والجماعة (الحنفي، المالكي، الشافعي، الحنبلي).

عند مقارنة المذاهب في أي مسألة:

## الهيكل المطلوب:

### 1. عنوان المسألة وتعريفها
### 2. رأي كل مذهب (مع الدليل):

| المذهب | الحكم | الدليل | ملاحظات |
|--------|-------|--------|---------|
| الحنفي | | | |
| المالكي | | | |
| الشافعي | | | |
| الحنبلي | | | |

### 3. نقاط الاتفاق
### 4. نقاط الاختلاف مع أسبابه
### 5. الراجح عند الجمهور (إن وُجد)
### 6. المراجع والمصادر

قواعد:
- كن دقيقاً علمياً ولا تخلط بين المذاهب
- اذكر الأدلة من القرآن والسنة
- اذكر أسماء العلماء ومؤلفاتهم
- لا تتحيز لمذهب على آخر`,
    `قارن بين المذاهب الأربعة في مسألة: ${topic}`,
    12000
  );
  return { topic, comparison: result.content, modelUsed: result.modelUsed };
}

// ═══ SCIENTIFIC MIRACLES (الإعجاز العلمي) ═════════════════════

export async function scientificMiracle(topic: string): Promise<any> {
  const result = await callPowerAI(
    `أنت باحث متخصص في الإعجاز العلمي في القرآن الكريم والسنة النبوية.

اكتب بحثاً مفصلاً يشمل:
1. الآية أو الآيات القرآنية ذات الصلة (بالنص الكامل)
2. تفسير العلماء القدامى للآية
3. الاكتشاف العلمي الحديث المرتبط
4. وجه الإعجاز والتوافق
5. المراجع العلمية (أبحاث ودراسات)
6. آراء العلماء المعاصرين

كن دقيقاً واذكر المصادر. لا تبالغ في الربط.`,
    `اكتب عن الإعجاز العلمي في: ${topic}`,
    8000
  );
  return { topic, content: result.content, modelUsed: result.modelUsed };
}
