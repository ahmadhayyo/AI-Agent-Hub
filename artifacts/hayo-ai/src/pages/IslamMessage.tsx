/**
 * رسالة الإسلام — القرآن الكريم | الحديث النبوي | المذاهب الأربعة | الإعجاز العلمي
 * Real data from: api.alquran.cloud, spa5k/tafsir_api, fawazahmed0/hadith-api
 */
import { useState, useEffect } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { toast } from "sonner";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import {
  Home, Loader2, Search, BookOpen, Book, Scale, Sparkles,
  ChevronDown, ChevronRight, Copy, ExternalLink, Star,
} from "lucide-react";

type Section = "quran" | "hadith" | "madhahib" | "miracles";

export default function IslamMessage() {
  const { isAuthenticated } = useAuth();
  const { t } = useTranslation();
  const [section, setSection] = useState<Section>("quran");

  // ═══ Quran State ═══
  const [selectedSurah, setSelectedSurah] = useState<number | null>(null);
  const [quranSearch, setQuranSearch] = useState("");
  const [tafsirAyah, setTafsirAyah] = useState<{ surah: number; ayah: number } | null>(null);

  const surahsQ = trpc.islam.listSurahs.useQuery();
  const surahDataQ = trpc.islam.getSurah.useQuery(
    { number: selectedSurah || 1 },
    { enabled: !!selectedSurah }
  );
  const tafsirQ = trpc.islam.getTafsir.useQuery(
    { surah: tafsirAyah?.surah || 1, ayah: tafsirAyah?.ayah || 1 },
    { enabled: !!tafsirAyah }
  );
  const searchQuranMut = trpc.islam.searchQuran.useMutation();

  // ═══ Hadith State ═══
  const [hadithSearch, setHadithSearch] = useState("");
  const [hadithBook, setHadithBook] = useState("all");
  const searchHadithMut = trpc.islam.searchHadith.useMutation();

  // ═══ Madhahib State ═══
  const [madhabTopic, setMadhabTopic] = useState("");
  const compareMut = trpc.islam.compareMadhahib.useMutation();

  // ═══ Miracles State ═══
  const [miracleTopic, setMiracleTopic] = useState("");
  const miracleMut = trpc.islam.scientificMiracle.useMutation();

  const SECTIONS = [
    { id: "quran" as Section, icon: BookOpen, label: "القرآن الكريم", color: "from-emerald-600 to-teal-600", emoji: "📖" },
    { id: "hadith" as Section, icon: Book, label: "الحديث النبوي", color: "from-amber-600 to-orange-600", emoji: "📜" },
    { id: "madhahib" as Section, icon: Scale, label: "المذاهب الأربعة", color: "from-violet-600 to-purple-600", emoji: "⚖️" },
    { id: "miracles" as Section, icon: Sparkles, label: "الإعجاز العلمي", color: "from-blue-600 to-cyan-600", emoji: "🔬" },
  ];

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white" dir="rtl">
      {/* Header */}
      <header className="h-14 bg-[#0f0f1a] border-b border-white/5 flex items-center justify-between px-4 sticky top-0 z-30 backdrop-blur-xl">
        <div className="flex items-center gap-3">
          <Link href="/" className="text-gray-400 hover:text-white"><Home className="w-4 h-4" /></Link>
          <div className="w-px h-5 bg-white/10" />
          <span className="text-lg">🕌</span>
          <span className="font-bold text-sm">رسالة الإسلام</span>
        </div>
        <LanguageSwitcher />
      </header>

      <div className="max-w-6xl mx-auto p-4 md:p-6 space-y-6">
        {/* Section Tabs */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {SECTIONS.map(s => (
            <button key={s.id} onClick={() => setSection(s.id)}
              className={`flex items-center gap-3 p-4 rounded-2xl border transition-all ${section === s.id ? "bg-white/5 border-white/20 shadow-lg" : "border-white/5 hover:border-white/10"}`}>
              <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${s.color} flex items-center justify-center shrink-0`}>
                <s.icon className="w-5 h-5 text-white" />
              </div>
              <div className="text-right">
                <p className="font-bold text-sm">{s.label}</p>
              </div>
            </button>
          ))}
        </div>

        {/* ═══════ QURAN SECTION ═══════ */}
        {section === "quran" && (
          <div className="space-y-6">
            {/* Search */}
            <div className="bg-white/5 border border-white/10 rounded-2xl p-4 flex gap-3">
              <Search className="w-5 h-5 text-emerald-400 shrink-0 mt-2" />
              <div className="flex-1 space-y-2">
                <input value={quranSearch} onChange={e => setQuranSearch(e.target.value)} placeholder="ابحث في القرآن... مثال: الرحمن، الصبر، الجنة..."
                  className="w-full bg-transparent border-b border-white/10 pb-2 text-sm focus:outline-none focus:border-emerald-500/50" onKeyDown={e => { if (e.key === "Enter" && quranSearch.trim()) searchQuranMut.mutate({ query: quranSearch }); }} />
                {searchQuranMut.isPending && <p className="text-xs text-emerald-400 animate-pulse">جاري البحث...</p>}
                {searchQuranMut.data && (
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    <p className="text-xs text-gray-400">{searchQuranMut.data.count} نتيجة</p>
                    {searchQuranMut.data.matches?.slice(0, 15).map((m: any, i: number) => (
                      <div key={i} className="p-2 rounded-lg bg-white/5 border border-white/5 cursor-pointer hover:border-emerald-500/30" onClick={() => { setSelectedSurah(m.surah.number); setTafsirAyah({ surah: m.surah.number, ayah: m.numberInSurah }); }}>
                        <p className="text-sm font-arabic leading-loose">{m.text}</p>
                        <p className="text-[10px] text-gray-500 mt-1">{m.surah.name} — الآية {m.numberInSurah}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Surah List */}
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2">
              {surahsQ.data?.slice(0, 114).map((s: any) => (
                <button key={s.number} onClick={() => { setSelectedSurah(s.number); setTafsirAyah(null); }}
                  className={`p-3 rounded-xl border text-center transition-all ${selectedSurah === s.number ? "bg-emerald-500/10 border-emerald-500/30" : "border-white/5 hover:border-white/10"}`}>
                  <span className="text-lg font-bold text-emerald-400">{s.number}</span>
                  <p className="text-xs font-bold mt-1">{s.name}</p>
                  <p className="text-[9px] text-gray-500">{s.englishName} • {s.numberOfAyahs} آية</p>
                </button>
              ))}
            </div>

            {/* Surah Content */}
            {surahDataQ.data && (
              <div className="bg-white/5 border border-white/10 rounded-2xl p-6 space-y-4">
                <div className="text-center space-y-2">
                  <h2 className="text-2xl font-bold">{surahDataQ.data.name}</h2>
                  <p className="text-sm text-gray-400">{surahDataQ.data.englishName} — {surahDataQ.data.revelationType === "Meccan" ? "مكية" : "مدنية"} — {surahDataQ.data.numberOfAyahs} آية</p>
                </div>
                <div className="space-y-3">
                  {surahDataQ.data.ayahs?.map((ayah: any) => (
                    <div key={ayah.numberInSurah} className="group flex gap-3 p-3 rounded-xl hover:bg-white/5 transition-all">
                      <span className="w-8 h-8 rounded-full bg-emerald-500/10 text-emerald-400 flex items-center justify-center text-xs font-bold shrink-0">{ayah.numberInSurah}</span>
                      <div className="flex-1">
                        <p className="text-lg font-arabic leading-[2.5] text-white/90">{ayah.text}</p>
                        <button onClick={() => setTafsirAyah({ surah: selectedSurah!, ayah: ayah.numberInSurah })}
                          className="opacity-0 group-hover:opacity-100 text-[10px] text-emerald-400 mt-1 hover:underline">📖 تفسير الآية</button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tafsir Panel */}
            {tafsirAyah && tafsirQ.data && (
              <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-2xl p-5 space-y-3">
                <h3 className="font-bold text-emerald-400 flex items-center gap-2"><BookOpen className="w-4 h-4" /> تفسير الآية {tafsirAyah.surah}:{tafsirAyah.ayah}</h3>
                <div className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">{tafsirQ.data.text}</div>
              </div>
            )}
          </div>
        )}

        {/* ═══════ HADITH SECTION ═══════ */}
        {section === "hadith" && (
          <div className="space-y-6">
            {/* Book Selection */}
            <div className="grid grid-cols-3 sm:grid-cols-5 gap-2">
              <button onClick={() => setHadithBook("all")} className={`p-2 rounded-xl border text-center text-xs ${hadithBook === "all" ? "bg-amber-500/10 border-amber-500/30 text-amber-400" : "border-white/5 text-gray-400"}`}>الكل</button>
              {Object.entries({ bukhari: "البخاري", muslim: "مسلم", tirmidhi: "الترمذي", abudawud: "أبو داود", nasai: "النسائي", ibnmajah: "ابن ماجه", malik: "مالك", ahmad: "أحمد", darimi: "الدارمي" }).map(([id, name]) => (
                <button key={id} onClick={() => setHadithBook(id)} className={`p-2 rounded-xl border text-center text-xs ${hadithBook === id ? "bg-amber-500/10 border-amber-500/30 text-amber-400" : "border-white/5 text-gray-400"}`}>{name}</button>
              ))}
            </div>

            {/* Search */}
            <div className="bg-white/5 border border-white/10 rounded-2xl p-4 space-y-3">
              <div className="flex gap-3">
                <input value={hadithSearch} onChange={e => setHadithSearch(e.target.value)} placeholder="ابحث عن أحاديث... مثال: الوضوء، الصلاة، الصيام، الصدقة..."
                  className="flex-1 bg-transparent border-b border-white/10 pb-2 text-sm focus:outline-none focus:border-amber-500/50" onKeyDown={e => { if (e.key === "Enter") searchHadithMut.mutate({ query: hadithSearch, book: hadithBook }); }} />
                <Button onClick={() => searchHadithMut.mutate({ query: hadithSearch, book: hadithBook })} disabled={searchHadithMut.isPending || !hadithSearch.trim()} className="gap-2 bg-gradient-to-r from-amber-600 to-orange-600">
                  {searchHadithMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} بحث
                </Button>
              </div>
              {/* Quick Topics */}
              <div className="flex flex-wrap gap-2">
                {["الوضوء", "الصلاة", "الصيام", "الزكاة", "الحج", "بر الوالدين", "الصدقة", "الصبر", "التوبة", "الدعاء"].map(topic => (
                  <button key={topic} onClick={() => { setHadithSearch(topic); searchHadithMut.mutate({ query: topic, book: hadithBook }); }}
                    className="text-[10px] px-2.5 py-1 rounded-lg border border-white/5 text-gray-400 hover:border-amber-500/30 hover:text-amber-400">{topic}</button>
                ))}
              </div>
            </div>

            {/* Results */}
            {searchHadithMut.data && (
              <div className="bg-white/5 border border-white/10 rounded-2xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-bold text-amber-400">📜 نتائج البحث: {searchHadithMut.data.query}</h3>
                  <span className="text-[10px] text-gray-500">نموذج: {searchHadithMut.data.modelUsed}</span>
                </div>
                <div className="prose prose-invert prose-sm max-w-none">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{searchHadithMut.data.results}</ReactMarkdown>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ═══════ MADHAHIB SECTION ═══════ */}
        {section === "madhahib" && (
          <div className="space-y-6">
            <div className="bg-white/5 border border-white/10 rounded-2xl p-5 space-y-4">
              <div className="text-center space-y-2">
                <Scale className="w-10 h-10 text-violet-400 mx-auto" />
                <h2 className="text-xl font-bold">مقارنة المذاهب الأربعة</h2>
                <p className="text-sm text-gray-400">الحنفي • المالكي • الشافعي • الحنبلي</p>
              </div>
              <input value={madhabTopic} onChange={e => setMadhabTopic(e.target.value)} placeholder="اكتب المسألة الفقهية... مثال: صلاة المسافر، القنوت في الفجر، مسح الخفين..."
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-violet-500/50" onKeyDown={e => { if (e.key === "Enter") compareMut.mutate({ topic: madhabTopic }); }} />
              <div className="flex flex-wrap gap-2">
                {["صلاة المسافر", "القنوت في الفجر", "مسح الخفين", "قراءة الفاتحة خلف الإمام", "التشهد الأول", "زكاة الفطر", "صيام المسافر", "النية في الصيام"].map(t => (
                  <button key={t} onClick={() => { setMadhabTopic(t); compareMut.mutate({ topic: t }); }}
                    className="text-[10px] px-2.5 py-1 rounded-lg border border-white/5 text-gray-400 hover:border-violet-500/30 hover:text-violet-400">{t}</button>
                ))}
              </div>
              <Button onClick={() => compareMut.mutate({ topic: madhabTopic })} disabled={compareMut.isPending || !madhabTopic.trim()} className="w-full gap-2 bg-gradient-to-r from-violet-600 to-purple-600">
                {compareMut.isPending ? <><Loader2 className="w-4 h-4 animate-spin" /> AI يقارن بين المذاهب...</> : <><Scale className="w-4 h-4" /> مقارنة بين المذاهب</>}
              </Button>
            </div>

            {compareMut.data && (
              <div className="bg-white/5 border border-white/10 rounded-2xl p-5">
                <h3 className="font-bold text-violet-400 mb-4">⚖️ {compareMut.data.topic}</h3>
                <div className="prose prose-invert prose-sm max-w-none [&_table]:w-full [&_table]:text-xs [&_th]:bg-violet-500/10 [&_th]:px-3 [&_th]:py-2 [&_td]:px-3 [&_td]:py-2 [&_td]:border-b [&_td]:border-white/5">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{compareMut.data.comparison}</ReactMarkdown>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ═══════ MIRACLES SECTION ═══════ */}
        {section === "miracles" && (
          <div className="space-y-6">
            <div className="bg-white/5 border border-white/10 rounded-2xl p-5 space-y-4">
              <div className="text-center space-y-2">
                <Sparkles className="w-10 h-10 text-cyan-400 mx-auto" />
                <h2 className="text-xl font-bold">الإعجاز العلمي في القرآن والسنة</h2>
              </div>
              <input value={miracleTopic} onChange={e => setMiracleTopic(e.target.value)} placeholder="اكتب الموضوع... مثال: خلق الإنسان، الجبال أوتاد، توسع الكون..."
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-cyan-500/50" onKeyDown={e => { if (e.key === "Enter") miracleMut.mutate({ topic: miracleTopic }); }} />
              <div className="flex flex-wrap gap-2">
                {["خلق الإنسان من طين", "توسع الكون", "الجبال أوتاد", "ظلمات البحر", "دورة الماء", "الحديد أنزلناه", "البصمة والأصابع", "النحل والشفاء"].map(t => (
                  <button key={t} onClick={() => { setMiracleTopic(t); miracleMut.mutate({ topic: t }); }}
                    className="text-[10px] px-2.5 py-1 rounded-lg border border-white/5 text-gray-400 hover:border-cyan-500/30 hover:text-cyan-400">{t}</button>
                ))}
              </div>
              <Button onClick={() => miracleMut.mutate({ topic: miracleTopic })} disabled={miracleMut.isPending || !miracleTopic.trim()} className="w-full gap-2 bg-gradient-to-r from-blue-600 to-cyan-600">
                {miracleMut.isPending ? <><Loader2 className="w-4 h-4 animate-spin" /> AI يبحث...</> : <><Sparkles className="w-4 h-4" /> اكتشف الإعجاز العلمي</>}
              </Button>
            </div>

            {miracleMut.data && (
              <div className="bg-white/5 border border-white/10 rounded-2xl p-5">
                <h3 className="font-bold text-cyan-400 mb-4">🔬 {miracleMut.data.topic}</h3>
                <div className="prose prose-invert prose-sm max-w-none">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{miracleMut.data.content}</ReactMarkdown>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
