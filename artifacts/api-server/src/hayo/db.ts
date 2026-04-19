import { db } from "@workspace/db";
import {
  users, conversations, messages, uploadedFiles,
  subscriptionPlans, subscriptions, usageRecords, apiKeys, integrations, subscriptionCodes,
  type User, type InsertUser, type Conversation, type InsertConversation,
  type MessageRow, type InsertMessage, type UploadedFile, type InsertUploadedFile,
  type SubscriptionPlan, type InsertSubscriptionPlan, type Subscription, type InsertSubscription,
  type ApiKey, type InsertApiKey, type UsageRecord, type Integration,
} from "@workspace/db/schema";
import { eq, desc, and, sql, gte, lte, count, isNotNull, gt } from "drizzle-orm";
import { createHash, randomBytes } from "crypto";
import { hashPassword } from "./auth";

export type { User, Conversation, MessageRow, UploadedFile, SubscriptionPlan, Subscription, ApiKey, UsageRecord, Integration };

// Guard function to ensure database is available
function ensureDb() {
  if (!db) {
    throw new Error("[Database] Database is not available. Make sure DATABASE_URL is set.");
  }
  return db;
}

// ==================== Users ====================
export async function upsertUser(user: InsertUser): Promise<void> {
  const database = ensureDb();
  const now = new Date();
  await database.insert(users).values({ ...user, updatedAt: now, lastSignedIn: now })
    .onConflictDoUpdate({
      target: users.openId,
      set: {
        name: user.name,
        email: user.email,
        lastSignedIn: now,
        updatedAt: now,
        ...(user.role ? { role: user.role } : {}),
      },
    });
}

const OWNER_EMAIL = "Fmf0038@gmail.com";

export async function createUser(data: { name: string; email: string; password: string }): Promise<User> {
  const normalizedEmail = data.email.toLowerCase().trim();
  const existing = await db.select().from(users).where(sql`lower(${users.email}) = ${normalizedEmail}`).limit(1);
  if (existing[0]) throw new Error("البريد الإلكتروني مسجل مسبقاً");

  const openId = `local_${randomBytes(16).toString("hex")}`;
  const passwordHash = hashPassword(data.password);
  const isOwner = normalizedEmail === OWNER_EMAIL.toLowerCase();
  const isFirstUser = (await db.select({ c: count() }).from(users))[0]?.c === 0;

  const result = await db.insert(users).values({
    openId,
    name: data.name,
    email: normalizedEmail,
    passwordHash,
    loginMethod: "password",
    role: (isOwner || isFirstUser) ? "admin" : "user",
    lastSignedIn: new Date(),
  }).returning();

  // Ensure owner always has admin role (in case DB was reset)
  if (isOwner && result[0]?.role !== "admin") {
    await db.update(users).set({ role: "admin" }).where(eq(users.id, result[0].id));
    result[0].role = "admin";
  }

  return result[0];
}

export async function loginUser(email: string, password: string): Promise<User> {
  const normalizedEmail = email.toLowerCase().trim();
  const result = await db.select().from(users).where(sql`lower(${users.email}) = ${normalizedEmail}`).limit(1);
  const user = result[0];
  if (!user) throw new Error("البريد الإلكتروني أو كلمة المرور غير صحيحة");
  if (!user.passwordHash) throw new Error("يرجى استخدام طريقة تسجيل الدخول الصحيحة");

  const hash = hashPassword(password);
  if (hash !== user.passwordHash) throw new Error("البريد الإلكتروني أو كلمة المرور غير صحيحة");

  await db.update(users).set({ lastSignedIn: new Date(), updatedAt: new Date() }).where(eq(users.id, user.id));
  return user;
}

export async function getUserById(id: number): Promise<User | undefined> {
  const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
  return result[0];
}

export async function getAllUsers(): Promise<User[]> {
  return db.select().from(users).orderBy(desc(users.createdAt));
}

// ==================== Conversations ====================
export async function createConversation(data: InsertConversation): Promise<number> {
  const result = await db.insert(conversations).values(data).returning({ id: conversations.id });
  return result[0].id;
}

export async function getUserConversations(userId: number): Promise<Conversation[]> {
  return db.select().from(conversations).where(eq(conversations.userId, userId)).orderBy(desc(conversations.updatedAt));
}

export async function getConversation(id: number, userId: number): Promise<Conversation | undefined> {
  const result = await db.select().from(conversations)
    .where(and(eq(conversations.id, id), eq(conversations.userId, userId))).limit(1);
  return result[0];
}

export async function updateConversationTitle(id: number, title: string): Promise<void> {
  await db.update(conversations).set({ title, updatedAt: new Date() }).where(eq(conversations.id, id));
}

export async function deleteConversation(id: number): Promise<void> {
  await db.delete(messages).where(eq(messages.conversationId, id));
  await db.delete(conversations).where(eq(conversations.id, id));
}

// ==================== Messages ====================
export async function addMessage(data: InsertMessage): Promise<number> {
  const result = await db.insert(messages).values(data).returning({ id: messages.id });
  await db.update(conversations).set({ updatedAt: new Date() }).where(eq(conversations.id, data.conversationId));
  return result[0].id;
}

export async function getConversationMessages(conversationId: number): Promise<MessageRow[]> {
  return db.select().from(messages)
    .where(eq(messages.conversationId, conversationId))
    .orderBy(messages.createdAt);
}

// ==================== Files ====================
export async function saveUploadedFile(data: InsertUploadedFile): Promise<number> {
  const result = await db.insert(uploadedFiles).values(data).returning({ id: uploadedFiles.id });
  return result[0].id;
}

export async function getUserFiles(userId: number): Promise<UploadedFile[]> {
  return db.select().from(uploadedFiles)
    .where(eq(uploadedFiles.userId, userId))
    .orderBy(desc(uploadedFiles.createdAt));
}

export async function getFileById(id: number): Promise<UploadedFile | undefined> {
  const result = await db.select().from(uploadedFiles).where(eq(uploadedFiles.id, id)).limit(1);
  return result[0];
}

export async function deleteFile(id: number, userId: number): Promise<void> {
  await db.delete(uploadedFiles)
    .where(and(eq(uploadedFiles.id, id), eq(uploadedFiles.userId, userId)));
}

// ==================== Plans ====================
export async function getActivePlans(): Promise<SubscriptionPlan[]> {
  return db.select().from(subscriptionPlans)
    .where(eq(subscriptionPlans.isActive, true))
    .orderBy(subscriptionPlans.sortOrder);
}

export async function getPlanById(id: number): Promise<SubscriptionPlan | undefined> {
  const result = await db.select().from(subscriptionPlans).where(eq(subscriptionPlans.id, id)).limit(1);
  return result[0];
}

export async function seedDefaultPlans(): Promise<void> {
  const existing = await db.select({ c: count() }).from(subscriptionPlans);
  if ((existing[0]?.c ?? 0) > 0) {
    // Update existing plans with accurate pricing and limits
    await db.update(subscriptionPlans).set({
      displayName: "تجريبي",
      description: "تجربة لمرة واحدة — 3 أيام فقط",
      priceMonthly: 0, priceYearly: 0,
      monthlyCredits: 30, dailyCreditLimit: 10,
      dailyMessageLimit: 10, monthlyMessageLimit: 30,
      allowedModels: "haiku",
      maxAgentPipelines: 1, maxWarRoomBattles: 1,
      maxFileUploadMB: 5,
      canUseSandbox: false, canUseWebSearch: false, canUseImageGen: false, canUseFileCreation: false,
    }).where(eq(subscriptionPlans.name, "free"));

    await db.update(subscriptionPlans).set({
      displayName: "المبتدئ",
      description: "للاستخدام الشخصي والطلاب",
      priceMonthly: 999, priceYearly: 9588,
      monthlyCredits: 500, dailyCreditLimit: 25,
      dailyMessageLimit: 25, monthlyMessageLimit: 500,
      allowedModels: "haiku,sonnet",
      maxAgentPipelines: 3, maxWarRoomBattles: 5,
      maxFileUploadMB: 15,
      canUseSandbox: false, canUseWebSearch: true, canUseImageGen: false, canUseFileCreation: true,
    }).where(eq(subscriptionPlans.name, "starter"));

    await db.update(subscriptionPlans).set({
      displayName: "الاحترافي",
      description: "للمحترفين والمستقلين",
      priceMonthly: 2999, priceYearly: 28788,
      monthlyCredits: 2000, dailyCreditLimit: 100,
      dailyMessageLimit: 100, monthlyMessageLimit: 2000,
      allowedModels: "haiku,sonnet,opus",
      maxAgentPipelines: 30, maxWarRoomBattles: 30,
      maxFileUploadMB: 50,
      canUseSandbox: true, canUseWebSearch: true, canUseImageGen: true, canUseFileCreation: true,
    }).where(eq(subscriptionPlans.name, "pro"));

    await db.update(subscriptionPlans).set({
      displayName: "الأعمال",
      description: "للشركات والفرق الكبيرة",
      priceMonthly: 7999, priceYearly: 76788,
      monthlyCredits: 8000, dailyCreditLimit: 400,
      dailyMessageLimit: 500, monthlyMessageLimit: 10000,
      allowedModels: "haiku,sonnet,opus",
      maxAgentPipelines: 200, maxWarRoomBattles: -1,
      maxFileUploadMB: 100,
      canUseSandbox: true, canUseWebSearch: true, canUseImageGen: true, canUseFileCreation: true,
      prioritySupport: true,
    }).where(eq(subscriptionPlans.name, "business"));

    return;
  }

  await db.insert(subscriptionPlans).values([
    {
      name: "free",
      displayName: "تجريبي",
      description: "تجربة لمرة واحدة — 3 أيام فقط",
      priceMonthly: 0, priceYearly: 0,
      monthlyCredits: 30, dailyCreditLimit: 10,
      dailyMessageLimit: 10, monthlyMessageLimit: 30,
      allowedModels: "haiku",
      maxAgentPipelines: 1, maxWarRoomBattles: 1,
      maxFileUploadMB: 5, canUseSandbox: false, canUseWebSearch: false, canUseImageGen: false, canUseFileCreation: false,
      sortOrder: 0,
    },
    {
      name: "starter",
      displayName: "المبتدئ",
      description: "للاستخدام الشخصي والطلاب",
      priceMonthly: 999, priceYearly: 9588,
      monthlyCredits: 500, dailyCreditLimit: 25,
      dailyMessageLimit: 25, monthlyMessageLimit: 500,
      allowedModels: "haiku,sonnet",
      maxAgentPipelines: 3, maxWarRoomBattles: 5,
      maxFileUploadMB: 15, canUseSandbox: false, canUseWebSearch: true, canUseImageGen: false, canUseFileCreation: true,
      sortOrder: 1,
    },
    {
      name: "pro",
      displayName: "الاحترافي",
      description: "للمحترفين والمستقلين",
      priceMonthly: 2999, priceYearly: 28788,
      monthlyCredits: 2000, dailyCreditLimit: 100,
      dailyMessageLimit: 100, monthlyMessageLimit: 2000,
      allowedModels: "haiku,sonnet,opus",
      maxAgentPipelines: 30, maxWarRoomBattles: 30,
      maxFileUploadMB: 50, canUseSandbox: true, canUseWebSearch: true, canUseImageGen: true, canUseFileCreation: true,
      sortOrder: 2,
    },
    {
      name: "business",
      displayName: "الأعمال",
      description: "للشركات والفرق الكبيرة",
      priceMonthly: 7999, priceYearly: 76788,
      monthlyCredits: 8000, dailyCreditLimit: 400,
      dailyMessageLimit: 500, monthlyMessageLimit: 10000,
      allowedModels: "haiku,sonnet,opus",
      maxAgentPipelines: 200, maxWarRoomBattles: -1,
      maxFileUploadMB: 100, canUseSandbox: true, canUseWebSearch: true, canUseImageGen: true, canUseFileCreation: true, prioritySupport: true,
      sortOrder: 3,
    },
  ]);
  console.log("[DB] Default plans seeded");
}

// ==================== Owner Account Seed ====================
const OWNER_PASSWORD_ENV = process.env.OWNER_PASSWORD;

export async function seedOwnerAccount(): Promise<void> {
  try {
    const ownerEmailLower = OWNER_EMAIL.toLowerCase();
    const existing = await db.select().from(users).where(sql`lower(${users.email}) = ${ownerEmailLower}`).limit(1);
    if (existing.length > 0) {
      // Ensure owner always has admin role
      if (existing[0].role !== "admin") {
        await db.update(users).set({ role: "admin", updatedAt: new Date() }).where(eq(users.id, existing[0].id));
        console.log("[DB] Owner role restored to admin");
      }
      return;
    }
    // Create owner account on first startup
    const ownerPassword = OWNER_PASSWORD_ENV || "6088amhA+";
    const openId = `local_${randomBytes(16).toString("hex")}`;
    await db.insert(users).values({
      openId,
      name: "مالك المنصة",
      email: OWNER_EMAIL,
      passwordHash: hashPassword(ownerPassword),
      loginMethod: "password",
      role: "admin",
      lastSignedIn: new Date(),
    });
    console.log("[DB] Owner account seeded successfully");
  } catch (err: any) {
    console.warn("[DB] Owner seed warning:", err.message);
  }
}

// ==================== Subscriptions ====================
export async function getUserActiveSubscription(userId: number): Promise<Subscription | undefined> {
  const now = new Date();
  const result = await db.select().from(subscriptions)
    .where(and(
      eq(subscriptions.userId, userId),
      eq(subscriptions.status, "active"),
      gte(subscriptions.endDate, now),
    ))
    .orderBy(desc(subscriptions.startDate))
    .limit(1);
  return result[0];
}

export async function createSubscription(data: InsertSubscription): Promise<number> {
  const result = await db.insert(subscriptions).values(data).returning({ id: subscriptions.id });
  return result[0].id;
}

// ==================== Usage ====================
export async function getOrCreateDailyUsage(userId: number): Promise<UsageRecord> {
  const today = new Date().toISOString().split("T")[0];
  const existing = await db.select().from(usageRecords)
    .where(and(eq(usageRecords.userId, userId), eq(usageRecords.date, today))).limit(1);
  if (existing[0]) return existing[0];

  const result = await db.insert(usageRecords)
    .values({ userId, date: today, messageCount: 0, tokenCount: 0 })
    .returning();
  return result[0];
}

export async function incrementUsage(userId: number, tokens: number = 0): Promise<void> {
  const today = new Date().toISOString().split("T")[0];
  await db.update(usageRecords).set({
    messageCount: sql`${usageRecords.messageCount} + 1`,
    tokenCount: sql`${usageRecords.tokenCount} + ${tokens}`,
    updatedAt: new Date(),
  }).where(and(eq(usageRecords.userId, userId), eq(usageRecords.date, today)));
}

// ── تكلفة كل عملية بالنقاط ──
export const CREDIT_COSTS: Record<string, number> = {
  // دردشة
  "chat":               2,
  // وكيل الكود
  "agent_pipeline":     30,
  "agent_chat":         2,
  "agent_fix":          3,
  "agent_fixAll":       10,
  // غرفة المعارك
  "war_room":           10,
  // بيئة التطوير BYOC
  "byoc_analyze":       3,
  // الأعمال المكتبية
  "pptx_generate":      8,
  "report_generate":    8,
  "office_tool":        2,
  "excel_process":      3,
  "file_convert":       0,
  "doc_chat":           3,
  "smart_template":     3,
  // الاتصالات
  "telegram_msg":       1,
  // الهندسة العكسية
  "reverse_decompile":  5,
  "reverse_analyze":    3,
  "reverse_edit_session": 10,
  "reverse_ai_modify":  3,
  "reverse_ai_search":  2,
  "reverse_rebuild":    5,
  "reverse_clone":      15,
  // منشئ التطبيقات
  "app_generate":       10,
  "app_build":          15,
  "app_review":         5,
  "app_desktop":        8,
  // EA Factory
  "ea_analyze":         10,
  "ea_generate":        15,
  "ea_fix":             5,
  // الدراسات
  "study_generate":     15,
  "study_followup":     3,
  // مصنع البرومبت
  "prompt_generate":    5,
  "prompt_refine":      3,
  "prompt_test":        3,
  // التداول
  "trading_analyze":    5,
  "trading_autosignal": 8,
  "trading_execute":    2,
};

// ── فحص الرصيد قبل العملية ──
export async function checkCredits(
  userId: number,
  operation: string,
  userPlan?: { dailyCreditLimit: number },
  userRole?: string
): Promise<{ allowed: boolean; remaining: number; cost: number; message?: string }> {
  const cost = CREDIT_COSTS[operation] ?? 1;
  if (cost === 0) return { allowed: true, remaining: 999, cost: 0 };

  // المسؤول (admin) لديه نقاط غير محدودة
  if (userRole === "admin") {
    return { allowed: true, remaining: 9999, cost };
  }

  // تحقق من دور المستخدم من قاعدة البيانات إن لم يُعطَ
  const userRecord = await db.select({ role: users.role }).from(users).where(eq(users.id, userId)).limit(1);
  if (userRecord[0]?.role === "admin") {
    return { allowed: true, remaining: 9999, cost };
  }

  const usage = await getOrCreateDailyUsage(userId);
  const todayCredits = usage.creditsUsed ?? 0;

  // احصل على الحد من الـ plan إذا لم يُعطَ
  let dailyLimit = userPlan?.dailyCreditLimit ?? 50;
  if (!userPlan) {
    const now = new Date();
    const activeSub = await db
      .select({ dailyCreditLimit: subscriptionPlans.dailyCreditLimit })
      .from(subscriptionCodes)
      .innerJoin(subscriptionPlans, eq(subscriptionCodes.planId, subscriptionPlans.id))
      .where(and(
        eq(subscriptionCodes.usedBy, userId),
        isNotNull(subscriptionCodes.usedAt),
        gt(subscriptionCodes.expiresAt, now)
      ))
      .limit(1);
    dailyLimit = activeSub[0]?.dailyCreditLimit ?? 50;
  }

  const realLimit = dailyLimit === -1 ? Infinity : dailyLimit;
  if (todayCredits + cost > realLimit) {
    return {
      allowed: false,
      remaining: Math.max(0, realLimit === Infinity ? 9999 : realLimit - todayCredits),
      cost,
      message: `وصلت إلى حد النقاط اليومي (${realLimit} نقطة). يُجدد رصيدك غداً أو قم بالترقية.`,
    };
  }
  return { allowed: true, remaining: realLimit === Infinity ? 9999 : realLimit - todayCredits - cost, cost };
}

// ── خصم النقاط بعد العملية ──
export async function deductCredits(userId: number, operation: string): Promise<void> {
  const cost = CREDIT_COSTS[operation] ?? 1;
  if (cost === 0) return;
  const today = new Date().toISOString().split("T")[0];
  await db.update(usageRecords).set({
    creditsUsed: sql`${usageRecords.creditsUsed} + ${cost}`,
    messageCount: sql`${usageRecords.messageCount} + 1`,
    updatedAt: new Date(),
  }).where(and(eq(usageRecords.userId, userId), eq(usageRecords.date, today)));
}

// ==================== Admin Stats ====================
export async function getAdminStats() {
  const [totalUsers, totalConversations, totalMessages, recentUsers] = await Promise.all([
    db.select({ c: count() }).from(users),
    db.select({ c: count() }).from(conversations),
    db.select({ c: count() }).from(messages),
    db.select().from(users).orderBy(desc(users.createdAt)).limit(5),
  ]);

  return {
    totalUsers: totalUsers[0]?.c ?? 0,
    totalConversations: totalConversations[0]?.c ?? 0,
    totalMessages: totalMessages[0]?.c ?? 0,
    recentUsers,
  };
}

// ==================== Integrations ====================
export async function getUserIntegrations(userId: number): Promise<Integration[]> {
  return db.select().from(integrations).where(eq(integrations.userId, userId));
}

export async function connectIntegration(data: { userId: number; provider: string; accessToken: string; metadata?: Record<string, unknown> }): Promise<void> {
  await db.insert(integrations).values({
    userId: data.userId,
    provider: data.provider,
    accessToken: data.accessToken,
    metadata: data.metadata,
    isActive: true,
  }).onConflictDoUpdate({
    target: [integrations.userId, integrations.provider],
    set: {
      accessToken: data.accessToken,
      metadata: data.metadata,
      isActive: true,
      updatedAt: new Date(),
    },
  });
}

export async function disconnectIntegration(userId: number, provider: string): Promise<void> {
  await db.update(integrations)
    .set({ isActive: false, updatedAt: new Date() })
    .where(and(eq(integrations.userId, userId), eq(integrations.provider, provider)));
}
