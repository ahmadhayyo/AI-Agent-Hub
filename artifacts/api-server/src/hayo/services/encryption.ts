import CryptoJS from "crypto-js";

const KEY = process.env.SESSION_SECRET || "hayo-ai-enc-key-change-in-prod-32";

export function encrypt(text: string): string {
  return CryptoJS.AES.encrypt(text, KEY).toString();
}

export function decrypt(ciphertext: string): string {
  return CryptoJS.AES.decrypt(ciphertext, KEY).toString(CryptoJS.enc.Utf8);
}
