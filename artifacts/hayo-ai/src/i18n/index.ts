import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import ar from "./locales/ar.json";
import en from "./locales/en.json";
import tr from "./locales/tr.json";
import pt from "./locales/pt.json";
import fr from "./locales/fr.json";

export const LANGUAGES = [
  { code: "ar", label: "العربية", flag: "🇸🇦", dir: "rtl" },
  { code: "en", label: "English", flag: "🇺🇸", dir: "ltr" },
  { code: "tr", label: "Türkçe", flag: "🇹🇷", dir: "ltr" },
  { code: "pt", label: "Português", flag: "🇧🇷", dir: "ltr" },
  { code: "fr", label: "Français", flag: "🇫🇷", dir: "ltr" },
] as const;

const savedLang = localStorage.getItem("hayo-lang") || "ar";

i18n.use(initReactI18next).init({
  resources: { ar: { translation: ar }, en: { translation: en }, tr: { translation: tr }, pt: { translation: pt }, fr: { translation: fr } },
  lng: savedLang,
  fallbackLng: "ar",
  interpolation: { escapeValue: false },
});

i18n.on("languageChanged", (lang) => {
  localStorage.setItem("hayo-lang", lang);
  const langConfig = LANGUAGES.find((l) => l.code === lang);
  document.documentElement.dir = langConfig?.dir || "rtl";
  document.documentElement.lang = lang;
});

const initialLang = LANGUAGES.find((l) => l.code === savedLang);
document.documentElement.dir = initialLang?.dir || "rtl";
document.documentElement.lang = savedLang;

export default i18n;
