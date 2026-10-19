import { randomUUID } from 'node:crypto';
import { index, integer, primaryKey, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { POLICY_TARGETS, type Access, type Estimate, type Operation, type StatementAnalysis, type Verb } from '../engines/types.js';

// Column names are mapped camelCase → snake_case by `casing: 'snake_case'` (see db/index.ts, drizzle.config.ts).

export const ACTIONS = ['allow', 'approve', 'deny'] as const;
export const ENGINES = ['postgres', 'mysql', 'mariadb'] as const;
export const SSL_MODES = ['disable', 'prefer', 'require', 'verify-full'] as const;
export const SURFACES = ['mcp', 'wire'] as const;
export const APPROVAL_STATUSES = ['pending', 'approved', 'denied', 'expired', 'cancelled'] as const;
export const AUDIT_DECISIONS = ['allowed', 'granted', 'approved', 'denied', 'rejected', 'expired', 'cancelled'] as const;

const id = () =>
  text()
    .primaryKey()
    .$defaultFn(() => randomUUID());
const timestamp = () => integer({ mode: 'timestamp_ms' });
const createdAt = () =>
  timestamp()
    .notNull()
    .$defaultFn(() => new Date());
const json = <T>() => text({ mode: 'json' }).$type<T>();
type OperationList = Operation[];

/** A database the proxy fronts. The proxy holds these credentials; clients never see them. */
export const databases = sqliteTable('databases', {
  id: id(),
  slug: text().notNull().unique(),
  name: text().notNull(),
  engine: text({ enum: ENGINES }).notNull().default('postgres'),
  host: text().notNull(),
  port: integer().notNull(),
  database: text().notNull(),
  user: text().notNull(),
  password: text().notNull().default(''),
  sslmode: text({ enum: SSL_MODES }).notNull().default('prefer'),
  /** Optional least-privilege login used for clients whose policy can never write. */
  readonlyUser: text(),
  readonlyPassword: text(),
  defaultRead: text({ enum: ACTIONS }).notNull().default('allow'),
  defaultWrite: text({ enum: ACTIONS }).notNull().default('approve'),
  defaultDdl: text({ enum: ACTIONS }).notNull().default('approve'),
  defaultAdmin: text({ enum: ACTIONS }).notNull().default('deny'),
  statementTimeoutMs: integer().notNull().default(30_000),
  maxRows: integer().notNull().default(200),
  enabled: integer({ mode: 'boolean' }).notNull().default(true),
  createdAt: createdAt(),
});

/** Clients: one token each, usable as an MCP bearer token and as the Postgres password for `username`. */
export const users = sqliteTable('users', {
  id: id(),
  name: text().notNull(),
  /** Postgres login name on the wire listener. */
  username: text().notNull().unique(),
  tokenHash: text().notNull().unique(),
  tokenPrefix: text().notNull(),
  /** SCRAM-SHA-256 verifier for wire logins (base64), derived from the token. */
  scramSalt: text().notNull(),
  scramIterations: integer().notNull(),
  scramStoredKey: text().notNull(),
  scramServerKey: text().notNull(),
  /** MySQL logins (hex): SHA1(SHA1(token)) for mysql_native_password, SHA256(SHA256(token)) for caching_sha2_password. */
  mysqlNativeHash: text(),
  mysqlSha2Hash: text(),
  enabled: integer({ mode: 'boolean' }).notNull().default(true),
  createdAt: createdAt(),
  lastUsedAt: timestamp(),
});

export const userDatabases = sqliteTable(
  'user_databases',
  {
    userId: text()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    databaseId: text()
      .notNull()
      .references(() => databases.id, { onDelete: 'cascade' }),
    allowMcp: integer({ mode: 'boolean' }).notNull().default(true),
    allowWire: integer({ mode: 'boolean' }).notNull().default(true),
  },
  (t) => [primaryKey({ columns: [t.userId, t.databaseId] })],
);

export const rules = sqliteTable(
  'rules',
  {
    id: id(),
    databaseId: text()
      .notNull()
      .references(() => databases.id, { onDelete: 'cascade' }),
    /** null = every client */
    userId: text().references(() => users.id, { onDelete: 'cascade' }),
    /** An operation (`write`) or a verb within one (`delete`). */
    operation: text({ enum: POLICY_TARGETS as [string, ...string[]] }).$type<(typeof POLICY_TARGETS)[number]>().notNull(),
    /** Table name or glob (`audit_*`, `app.*`); null = any table */
    tablePattern: text(),
    action: text({ enum: ACTIONS }).notNull(),
    note: text(),
    createdAt: createdAt(),
  },
  (t) => [index('rules_database_idx').on(t.databaseId)],
);

/** Trust windows: skip "ask" for matching accesses until expiry. Never overrides deny. */
export const grants = sqliteTable(
  'grants',
  {
    id: id(),
    databaseId: text()
      .notNull()
      .references(() => databases.id, { onDelete: 'cascade' }),
    /** null = every client */
    userId: text().references(() => users.id, { onDelete: 'cascade' }),
    /** An operation or verb; null = anything that asks */
    operation: text({ enum: POLICY_TARGETS as [string, ...string[]] }).$type<(typeof POLICY_TARGETS)[number]>(),
    /** null = any table */
    tablePattern: text(),
    /** null = until revoked */
    expiresAt: timestamp(),
    approvalId: text(),
    note: text(),
    createdAt: createdAt(),
  },
  (t) => [index('grants_database_idx').on(t.databaseId)],
);

export interface SessionInfo {
  applicationName?: string | null;
  transactionStatus?: 'idle' | 'transaction' | 'failed';
  transactionAgeMs?: number | null;
}

export const approvals = sqliteTable(
  'approvals',
  {
    id: id(),
    databaseId: text()
      .notNull()
      .references(() => databases.id, { onDelete: 'cascade' }),
    userId: text()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    surface: text({ enum: SURFACES }).notNull(),
    sql: text().notNull(),
    params: json<(string | null)[] | null>(),
    statements: json<StatementAnalysis[]>().notNull(),
    /** The accesses that needed a human (policy said "approve" and no trust window covered them). */
    asked: json<Access[]>().notNull(),
    operations: json<OperationList>().notNull(),
    verbs: json<Verb[]>().notNull().default([]),
    tables: json<string[]>().notNull(),
    estimate: json<Estimate | null>(),
    session: json<SessionInfo | null>(),
    status: text({ enum: APPROVAL_STATUSES }).notNull().default('pending'),
    createdAt: createdAt(),
    expiresAt: timestamp().notNull(),
    decidedAt: timestamp(),
    grantId: text(),
  },
  (t) => [index('approvals_status_idx').on(t.status, t.createdAt)],
);

/** Append-only log of every statement. Not FK'd so history survives deletes. */
export const audit = sqliteTable(
  'audit',
  {
    id: integer().primaryKey({ autoIncrement: true }),
    ts: createdAt(),
    databaseId: text().notNull(),
    userId: text().notNull(),
    surface: text({ enum: SURFACES }).notNull(),
    sql: text().notNull(),
    operations: json<OperationList>().notNull(),
    verbs: json<Verb[]>().notNull().default([]),
    tables: json<string[]>().notNull(),
    decision: text({ enum: AUDIT_DECISIONS }).notNull(),
    ruleId: text(),
    approvalId: text(),
    rowCount: integer(),
    sqlstate: text(),
    error: text(),
    durationMs: integer(),
  },
  (t) => [index('audit_database_idx').on(t.databaseId), index('audit_user_idx').on(t.userId)],
);

/** Browser Web Push subscriptions (PWA), keyed by push-service endpoint. */
export const pushSubscriptions = sqliteTable('push_subscriptions', {
  endpoint: text().primaryKey(),
  p256dh: text().notNull(),
  auth: text().notNull(),
  userAgent: text(),
  createdAt: createdAt(),
  lastSuccessAt: timestamp(),
});

/** Native iOS devices (APNs), for the future native app. */
export const apnsDevices = sqliteTable('apns_devices', {
  token: text().primaryKey(),
  environment: text({ enum: ['sandbox', 'production'] }).notNull(),
  createdAt: createdAt(),
});

export const settings = sqliteTable('settings', {
  key: text().primaryKey(),
  value: text().notNull(),
});
