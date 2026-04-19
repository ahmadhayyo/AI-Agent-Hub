import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

// Initialize database connection
// If DATABASE_URL is not set, db will be null but app can still start
let dbInstance: any = null;
let poolInstance: any = null;
let initialized = false;

function initializeDatabase() {
  if (initialized) return; // Already attempted initialization
  initialized = true;

  if (!process.env.DATABASE_URL) {
    console.warn("[Database] DATABASE_URL not set — database features will be unavailable");
    return;
  }

  try {
    poolInstance = new Pool({ connectionString: process.env.DATABASE_URL });
    dbInstance = drizzle(poolInstance, { schema });
    console.info("[Database] Connected successfully");
  } catch (err: any) {
    console.error("[Database] Connection failed:", err.message);
    dbInstance = null;
    poolInstance = null;
  }
}

// Initialize immediately but don't throw
initializeDatabase();

export const pool = poolInstance;
export const db = dbInstance;

export * from "./schema";
