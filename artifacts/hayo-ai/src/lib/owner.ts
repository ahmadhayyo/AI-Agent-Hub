const OWNER_EMAIL = (import.meta.env.VITE_OWNER_EMAIL || "Fmf0038@gmail.com")
  .trim()
  .toLowerCase();

type UserLike = {
  role?: string | null;
  email?: string | null;
} | null | undefined;

export function isOwnerUser(user: UserLike): boolean {
  if (!user || user.role !== "admin") return false;
  const email = typeof user.email === "string" ? user.email.trim().toLowerCase() : "";
  return email === OWNER_EMAIL;
}
