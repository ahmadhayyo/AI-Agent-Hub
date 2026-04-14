import {
  pgTable, pgEnum, serial, text, varchar, integer,
  boolean, timestamp, jsonb, index, uniqueIndex
} from "drizzle-orm/pg-core";

export const userRoleEnum = pgEnum("user_role", ["user", "admin"]);
export const messageRoleEnum = pgEnum("message_role", ["system", "user", "assistant"]);
export const subscriptionStatusEnum = pgEnum("subscription_status", ["active", "cancelled", "expired", "trial"]);

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  openId: varchar("openId", { length: 128 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  passwordHash: text("passwordHash"),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: userRoleEnum("role").default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
}, (t) => [index("users_email_idx").on(t.email)]);

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

export const conversations = pgTable("conversations", {
  id: serial("id").primaryKey(),
  userId: integer("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  title: varchar("title", { length: 255 }).default("محادثة جديدة").notNull(),
  systemPrompt: text("systemPrompt"),
  agentMode: varchar("agentMode", { length: 64 }).default("default"),
  model: varchar("model", { length: 64 }).default("default"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull(),
}, (t) => [index("conversations_userId_idx").on(t.userId)]);

export type Conversation = typeof conversations.$inferSelect;
export type InsertConversation = typeof conversations.$inferInsert;

export const messages = pgTable("messages", {
  id: serial("id").primaryKey(),
  conversationId: integer("conversationId").notNull().references(() => conversations.id, { onDelete: "cascade" }),
  role: messageRoleEnum("role").notNull(),
  content: text("content").notNull(),
  attachments: jsonb("attachments").$type<Array<{ name: string; url: string; type: string; size: number }>>(),
  agentSteps: jsonb("agentSteps").$type<Array<{ type: string; content: string; toolName?: string; success?: boolean }>>(),
  tokenCount: integer("tokenCount"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, (t) => [index("messages_conversationId_idx").on(t.conversationId)]);

export type MessageRow = typeof messages.$inferSelect;
export type InsertMessage = typeof messages.$inferInsert;

export const uploadedFiles = pgTable("uploadedFiles", {
  id: serial("id").primaryKey(),
  userId: integer("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  fileName: varchar("fileName", { length: 512 }).notNull(),
  fileKey: varchar("fileKey", { length: 512 }).notNull(),
  fileUrl: text("fileUrl").notNull(),
  mimeType: varchar("mimeType", { length: 128 }).notNull(),
  fileSize: integer("fileSize").notNull(),
  extractedText: text("extractedText"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type UploadedFile = typeof uploadedFiles.$inferSelect;
export type InsertUploadedFile = typeof uploadedFiles.$inferInsert;

export const subscriptionPlans = pgTable("subscriptionPlans", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 64 }).notNull().unique(),
  displayName: varchar("displayName", { length: 128 }).notNull(),
  description: text("description"),
  priceMonthly: integer("priceMonthly").default(0).notNull(),
  priceYearly: integer("priceYearly").default(0).notNull(),
  dailyMessageLimit: integer("dailyMessageLimit").default(10).notNull(),
  monthlyMessageLimit: integer("monthlyMessageLimit").default(100).notNull(),
  monthlyCredits: integer("monthlyCredits").default(50).notNull(),
  dailyCreditLimit: integer("dailyCreditLimit").default(10).notNull(),
  allowedModels: varchar("allowedModels", { length: 128 }).default("haiku").notNull(),
  maxAgentPipelines: integer("maxAgentPipelines").default(0).notNull(),
  maxWarRoomBattles: integer("maxWarRoomBattles").default(0).notNull(),
  maxFileUploadMB: integer("maxFileUploadMB").default(5).notNull(),
  maxCodeExecutionSec: integer("maxCodeExecutionSec").default(30).notNull(),
  canUseWebSearch: boolean("canUseWebSearch").default(false).notNull(),
  canUseImageGen: boolean("canUseImageGen").default(false).notNull(),
  canUseFileCreation: boolean("canUseFileCreation").default(false).notNull(),
  canUseSandbox: boolean("canUseSandbox").default(false).notNull(),
  prioritySupport: boolean("prioritySupport").default(false).notNull(),
  isActive: boolean("isActive").default(true).notNull(),
  sortOrder: integer("sortOrder").default(0).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull(),
});

export type SubscriptionPlan = typeof subscriptionPlans.$inferSelect;
export type InsertSubscriptionPlan = typeof subscriptionPlans.$inferInsert;

export const apiKeys = pgTable("apiKeys", {
  id: serial("id").primaryKey(),
  userId: integer("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  keyHash: varchar("keyHash", { length: 128 }).notNull().unique(),
  keyPrefix: varchar("keyPrefix", { length: 16 }).notNull(),
  label: varchar("label", { length: 128 }).default("Default Key").notNull(),
  planId: integer("planId").notNull(),
  isActive: boolean("isActive").default(true).notNull(),
  expiresAt: timestamp("expiresAt").notNull(),
  lastUsedAt: timestamp("lastUsedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull(),
});

export type ApiKey = typeof apiKeys.$inferSelect;
export type InsertApiKey = typeof apiKeys.$inferInsert;

export const usageRecords = pgTable("usageRecords", {
  id: serial("id").primaryKey(),
  userId: integer("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  date: varchar("date", { length: 10 }).notNull(),
  messageCount: integer("messageCount").default(0).notNull(),
  tokenCount: integer("tokenCount").default(0).notNull(),
  creditsUsed: integer("creditsUsed").default(0).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull(),
}, (t) => [index("usageRecords_userId_date_idx").on(t.userId, t.date)]);

export type UsageRecord = typeof usageRecords.$inferSelect;
export type InsertUsageRecord = typeof usageRecords.$inferInsert;

export const subscriptions = pgTable("subscriptions", {
  id: serial("id").primaryKey(),
  userId: integer("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  planId: integer("planId").notNull().references(() => subscriptionPlans.id),
  status: subscriptionStatusEnum("status").default("active").notNull(),
  startDate: timestamp("startDate").notNull(),
  endDate: timestamp("endDate").notNull(),
  amountPaid: integer("amountPaid").default(0).notNull(),
  paymentInfo: text("paymentInfo"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull(),
}, (t) => [index("subscriptions_userId_idx").on(t.userId)]);

export type Subscription = typeof subscriptions.$inferSelect;
export type InsertSubscription = typeof subscriptions.$inferInsert;

export const integrations = pgTable("integrations", {
  id: serial("id").primaryKey(),
  userId: integer("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  provider: varchar("provider", { length: 64 }).notNull(),
  accessToken: text("accessToken"),
  refreshToken: text("refreshToken"),
  tokenExpiry: timestamp("tokenExpiry"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>(),
  isActive: boolean("isActive").default(true).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull(),
}, (t) => [uniqueIndex("integrations_userId_provider_idx").on(t.userId, t.provider)]);

export type Integration = typeof integrations.$inferSelect;
export type InsertIntegration = typeof integrations.$inferInsert;

export const telegramBots = pgTable("telegramBots", {
  id: serial("id").primaryKey(),
  userId: integer("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  botToken: text("botToken").notNull(),
  botUsername: varchar("botUsername", { length: 128 }),
  isActive: boolean("isActive").default(true).notNull(),
  welcomeMessage: text("welcomeMessage"),
  systemPrompt: text("systemPrompt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull(),
}, (t) => [index("telegramBots_userId_idx").on(t.userId)]);

export type TelegramBot = typeof telegramBots.$inferSelect;
export type InsertTelegramBot = typeof telegramBots.$inferInsert;

export const appBuilds = pgTable("appBuilds", {
  id: serial("id").primaryKey(),
  userId: integer("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  appName: varchar("appName", { length: 255 }).notNull(),
  description: text("description"),
  expoSlug: varchar("expoSlug", { length: 255 }),
  expoJobId: varchar("expoJobId", { length: 255 }),
  status: varchar("status", { length: 50 }).default("pending").notNull(),
  platform: varchar("platform", { length: 20 }).default("android").notNull(),
  generatedCode: text("generatedCode"),
  downloadUrl: text("downloadUrl"),
  errorMessage: text("errorMessage"),
  buildLogsUrl: text("buildLogsUrl"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull(),
}, (t) => [index("appBuilds_userId_idx").on(t.userId)]);

export type AppBuild = typeof appBuilds.$inferSelect;
export type InsertAppBuild = typeof appBuilds.$inferInsert;

export const subscriptionCodes = pgTable("subscriptionCodes", {
  id: serial("id").primaryKey(),
  code: varchar("code", { length: 64 }).notNull().unique(),
  planId: integer("planId").notNull().references(() => subscriptionPlans.id),
  durationDays: integer("durationDays").notNull().default(30),
  createdBy: integer("createdBy").notNull().references(() => users.id),
  usedBy: integer("usedBy").references(() => users.id),
  usedAt: timestamp("usedAt"),
  expiresAt: timestamp("expiresAt"),
  note: text("note"),
  isActive: boolean("isActive").default(true).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, (t) => [
  index("subscriptionCodes_code_idx").on(t.code),
  index("subscriptionCodes_usedBy_idx").on(t.usedBy),
]);

export type SubscriptionCode = typeof subscriptionCodes.$inferSelect;
export type InsertSubscriptionCode = typeof subscriptionCodes.$inferInsert;

export const osintContacts = pgTable("osint_contacts", {
  id: serial("id").primaryKey(),
  phone: varchar("phone", { length: 20 }).notNull(),
  name: text("name"),
  carrier: varchar("carrier", { length: 128 }),
  location: text("location"),
  countryCode: varchar("country_code", { length: 5 }),
  countryName: varchar("country_name", { length: 128 }),
  dialCode: varchar("dial_code", { length: 10 }),
  source: varchar("source", { length: 128 }),
  lineType: varchar("line_type", { length: 32 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, (t) => [
  index("osint_contacts_phone_idx").on(t.phone),
  index("osint_contacts_country_idx").on(t.countryCode),
]);

export type OsintContact = typeof osintContacts.$inferSelect;
export type InsertOsintContact = typeof osintContacts.$inferInsert;

export const osintSearchLog = pgTable("osint_search_log", {
  id: serial("id").primaryKey(),
  userId: integer("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  toolType: varchar("tool_type", { length: 32 }).notNull(),
  query: varchar("query", { length: 512 }).notNull(),
  resultCount: integer("result_count").default(0).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, (t) => [
  index("osint_search_log_userId_idx").on(t.userId),
]);

export type OsintSearchLog = typeof osintSearchLog.$inferSelect;

export const osintCountryCoverage = pgTable("osint_country_coverage", {
  id: serial("id").primaryKey(),
  countryCode: varchar("country_code", { length: 5 }).notNull().unique(),
  countryName: varchar("country_name", { length: 128 }).notNull(),
  countryNameAr: varchar("country_name_ar", { length: 128 }),
  dialCode: varchar("dial_code", { length: 10 }).notNull(),
  region: varchar("region", { length: 64 }),
  recordCount: integer("record_count").default(0).notNull(),
  coverageLevel: varchar("coverage_level", { length: 20 }).default("basic").notNull(),
  source: varchar("source", { length: 128 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type OsintCountryCoverage = typeof osintCountryCoverage.$inferSelect;
