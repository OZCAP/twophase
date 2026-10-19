import { and, desc, eq, gt, inArray, isNull, lt, or } from 'drizzle-orm';
import type Database from 'better-sqlite3';
import { openDatabase, type Db } from './db/index.js';
import * as t from './db/schema.js';

export type Action = (typeof t.ACTIONS)[number];
export type Surface = (typeof t.SURFACES)[number];
export type ApprovalStatus = (typeof t.APPROVAL_STATUSES)[number];
export type AuditDecision = (typeof t.AUDIT_DECISIONS)[number];

export type DatabaseConfig = typeof t.databases.$inferSelect;
export type DatabaseInput = Omit<typeof t.databases.$inferInsert, 'id' | 'createdAt'>;
export type DatabaseAccess = { databaseId: string; allowMcp: boolean; allowWire: boolean };
type UserRow = typeof t.users.$inferSelect;
export type ProxyUser = Omit<UserRow, 'tokenHash' | 'scramSalt' | 'scramIterations' | 'scramStoredKey' | 'scramServerKey'> & {
  access: DatabaseAccess[];
};
export type ScramVerifier = Pick<UserRow, 'scramSalt' | 'scramIterations' | 'scramStoredKey' | 'scramServerKey'>;
export type Rule = typeof t.rules.$inferSelect;
export type Grant = typeof t.grants.$inferSelect;
export type Approval = typeof t.approvals.$inferSelect;
export type ApprovalInput = Omit<typeof t.approvals.$inferInsert, 'id' | 'createdAt' | 'status' | 'decidedAt' | 'grantId'>;
export type AuditEntry = typeof t.audit.$inferSelect;
export type AuditInput = Omit<typeof t.audit.$inferInsert, 'id' | 'ts'>;
export type PushSubscription = typeof t.pushSubscriptions.$inferSelect;
export type ApnsDevice = typeof t.apnsDevices.$inferSelect;

const MAX_STORED_SQL = 64 * 1024;
const capSql = (sql: string) => (sql.length > MAX_STORED_SQL ? `${sql.slice(0, MAX_STORED_SQL)}\n-- [truncated ${sql.length - MAX_STORED_SQL} chars]` : sql);
const activeAt = (now: Date) => or(isNull(t.grants.expiresAt), gt(t.grants.expiresAt, now));

/** All persistence goes through here. Synchronous: better-sqlite3 is, and it keeps call sites simple. */
export class Store {
  readonly db: Db;
  private sqlite: Database.Database;

  constructor(dataDir: string) {
    ({ db: this.db, sqlite: this.sqlite } = openDatabase(dataDir));
  }

  close() {
    this.sqlite.close();
  }

  // ── settings ──────────────────────────────────────────────

  getSetting(key: string): string | null {
    return this.db.select().from(t.settings).where(eq(t.settings.key, key)).get()?.value ?? null;
  }

  setSetting(key: string, value: string) {
    this.db.insert(t.settings).values({ key, value }).onConflictDoUpdate({ target: t.settings.key, set: { value } }).run();
  }

  deleteSetting(key: string) {
    this.db.delete(t.settings).where(eq(t.settings.key, key)).run();
  }

  // ── databases ─────────────────────────────────────────────

  listDatabases(): DatabaseConfig[] {
    return this.db.select().from(t.databases).orderBy(t.databases.name).all();
  }

  getDatabase(id: string): DatabaseConfig | null {
    return this.db.select().from(t.databases).where(eq(t.databases.id, id)).get() ?? null;
  }

  getDatabaseBySlug(slug: string): DatabaseConfig | null {
    return this.db.select().from(t.databases).where(eq(t.databases.slug, slug)).get() ?? null;
  }

  createDatabase(input: DatabaseInput): DatabaseConfig {
    return this.db.insert(t.databases).values(input).returning().get();
  }

  updateDatabase(id: string, patch: Partial<DatabaseInput>): DatabaseConfig | null {
    if (Object.keys(patch).length === 0) return this.getDatabase(id);
    return this.db.update(t.databases).set(patch).where(eq(t.databases.id, id)).returning().get() ?? null;
  }

  deleteDatabase(id: string): boolean {
    return this.db.delete(t.databases).where(eq(t.databases.id, id)).run().changes > 0;
  }

  // ── users (clients) ───────────────────────────────────────

  private withAccess(rows: UserRow[]): ProxyUser[] {
    if (rows.length === 0) return [];
    const links = this.db
      .select()
      .from(t.userDatabases)
      .where(inArray(t.userDatabases.userId, rows.map((r) => r.id)))
      .all();
    return rows.map(({ tokenHash: _h, scramSalt: _s, scramIterations: _i, scramStoredKey: _k, scramServerKey: _v, ...u }) => ({
      ...u,
      access: links
        .filter((l) => l.userId === u.id)
        .map((l) => ({ databaseId: l.databaseId, allowMcp: l.allowMcp, allowWire: l.allowWire })),
    }));
  }

  listUsers(): ProxyUser[] {
    return this.withAccess(this.db.select().from(t.users).orderBy(t.users.name).all());
  }

  getUser(id: string): ProxyUser | null {
    return this.withAccess(this.db.select().from(t.users).where(eq(t.users.id, id)).all())[0] ?? null;
  }

  getUserByTokenHash(hash: string): ProxyUser | null {
    return this.withAccess(this.db.select().from(t.users).where(eq(t.users.tokenHash, hash)).all())[0] ?? null;
  }

  getUserByUsername(username: string): (ProxyUser & { scram: ScramVerifier }) | null {
    const row = this.db.select().from(t.users).where(eq(t.users.username, username)).get();
    if (!row) return null;
    const { scramSalt, scramIterations, scramStoredKey, scramServerKey } = row;
    return { ...this.withAccess([row])[0], scram: { scramSalt, scramIterations, scramStoredKey, scramServerKey } };
  }

  usernameTaken(username: string): boolean {
    return !!this.db.select({ id: t.users.id }).from(t.users).where(eq(t.users.username, username)).get();
  }

  createUser(input: { name: string; username: string; tokenHash: string; tokenPrefix: string } & ScramVerifier, access: DatabaseAccess[]): ProxyUser {
    const id = this.db.transaction((tx) => {
      const { id } = tx.insert(t.users).values(input).returning({ id: t.users.id }).get();
      if (access.length) tx.insert(t.userDatabases).values(access.map((a) => ({ userId: id, ...a }))).run();
      return id;
    });
    return this.getUser(id)!;
  }

  updateUser(id: string, patch: { name?: string; enabled?: boolean; access?: DatabaseAccess[] }): ProxyUser | null {
    const { access, ...fields } = patch;
    this.db.transaction((tx) => {
      if (Object.keys(fields).length) tx.update(t.users).set(fields).where(eq(t.users.id, id)).run();
      if (access) {
        tx.delete(t.userDatabases).where(eq(t.userDatabases.userId, id)).run();
        const unique = [...new Map(access.map((a) => [a.databaseId, a])).values()];
        if (unique.length) tx.insert(t.userDatabases).values(unique.map((a) => ({ userId: id, ...a }))).run();
      }
    });
    return this.getUser(id);
  }

  setUserToken(id: string, token: { tokenHash: string; tokenPrefix: string } & ScramVerifier) {
    this.db.update(t.users).set(token).where(eq(t.users.id, id)).run();
  }

  touchUser(id: string) {
    this.db.update(t.users).set({ lastUsedAt: new Date() }).where(eq(t.users.id, id)).run();
  }

  deleteUser(id: string): boolean {
    return this.db.delete(t.users).where(eq(t.users.id, id)).run().changes > 0;
  }

  // ── rules ─────────────────────────────────────────────────

  listRules(filter: { databaseId?: string; userId?: string } = {}): Rule[] {
    return this.db
      .select()
      .from(t.rules)
      .where(
        and(
          filter.databaseId ? eq(t.rules.databaseId, filter.databaseId) : undefined,
          filter.userId ? eq(t.rules.userId, filter.userId) : undefined,
        ),
      )
      .orderBy(t.rules.createdAt)
      .all();
  }

  createRule(input: Omit<typeof t.rules.$inferInsert, 'id' | 'createdAt'>): Rule {
    return this.db.insert(t.rules).values(input).returning().get();
  }

  updateRule(id: string, patch: Partial<Pick<Rule, 'userId' | 'operation' | 'tablePattern' | 'action' | 'note'>>): Rule | null {
    if (Object.keys(patch).length === 0) return this.db.select().from(t.rules).where(eq(t.rules.id, id)).get() ?? null;
    return this.db.update(t.rules).set(patch).where(eq(t.rules.id, id)).returning().get() ?? null;
  }

  deleteRule(id: string): boolean {
    return this.db.delete(t.rules).where(eq(t.rules.id, id)).run().changes > 0;
  }

  // ── grants (trust windows) ────────────────────────────────

  listActiveGrants(filter: { databaseId?: string; userId?: string } = {}): Grant[] {
    return this.db
      .select()
      .from(t.grants)
      .where(
        and(
          activeAt(new Date()),
          filter.databaseId ? eq(t.grants.databaseId, filter.databaseId) : undefined,
          filter.userId ? or(isNull(t.grants.userId), eq(t.grants.userId, filter.userId)) : undefined,
        ),
      )
      .orderBy(desc(t.grants.createdAt))
      .all();
  }

  createGrant(input: Omit<typeof t.grants.$inferInsert, 'id' | 'createdAt'>): Grant {
    return this.db.insert(t.grants).values(input).returning().get();
  }

  deleteGrant(id: string): boolean {
    return this.db.delete(t.grants).where(eq(t.grants.id, id)).run().changes > 0;
  }

  // ── approvals ─────────────────────────────────────────────

  createApproval(input: ApprovalInput): Approval {
    return this.db
      .insert(t.approvals)
      .values({ ...input, sql: capSql(input.sql) })
      .returning()
      .get();
  }

  getApproval(id: string): Approval | null {
    return this.db.select().from(t.approvals).where(eq(t.approvals.id, id)).get() ?? null;
  }

  listApprovals(opts: { status?: ApprovalStatus; limit?: number }): Approval[] {
    return this.db
      .select()
      .from(t.approvals)
      .where(opts.status ? eq(t.approvals.status, opts.status) : undefined)
      .orderBy(desc(t.approvals.createdAt))
      .limit(opts.limit ?? 100)
      .all();
  }

  /** Transition a pending approval. Returns null if it was no longer pending (someone else won the race). */
  resolveApproval(id: string, status: Exclude<ApprovalStatus, 'pending'>, grantId: string | null = null): Approval | null {
    return (
      this.db
        .update(t.approvals)
        .set({ status, grantId, decidedAt: new Date() })
        .where(and(eq(t.approvals.id, id), eq(t.approvals.status, 'pending')))
        .returning()
        .get() ?? null
    );
  }

  expireStalePendingApprovals() {
    this.db
      .update(t.approvals)
      .set({ status: 'expired', decidedAt: new Date() })
      .where(eq(t.approvals.status, 'pending'))
      .run();
  }

  // ── audit ─────────────────────────────────────────────────

  addAudit(e: AuditInput): AuditEntry {
    return this.db
      .insert(t.audit)
      .values({ ...e, sql: capSql(e.sql) })
      .returning()
      .get();
  }

  listAudit(opts: { limit?: number; beforeId?: number; databaseId?: string; userId?: string }): AuditEntry[] {
    return this.db
      .select()
      .from(t.audit)
      .where(
        and(
          opts.beforeId ? lt(t.audit.id, opts.beforeId) : undefined,
          opts.databaseId ? eq(t.audit.databaseId, opts.databaseId) : undefined,
          opts.userId ? eq(t.audit.userId, opts.userId) : undefined,
        ),
      )
      .orderBy(desc(t.audit.id))
      .limit(opts.limit ?? 100)
      .all();
  }

  // ── Web Push subscriptions (PWA) ──────────────────────────

  upsertPushSubscription(sub: { endpoint: string; p256dh: string; auth: string; userAgent: string | null }) {
    this.db
      .insert(t.pushSubscriptions)
      .values(sub)
      .onConflictDoUpdate({ target: t.pushSubscriptions.endpoint, set: { p256dh: sub.p256dh, auth: sub.auth, userAgent: sub.userAgent } })
      .run();
  }

  listPushSubscriptions(): PushSubscription[] {
    return this.db.select().from(t.pushSubscriptions).all();
  }

  markPushDelivered(endpoint: string) {
    this.db.update(t.pushSubscriptions).set({ lastSuccessAt: new Date() }).where(eq(t.pushSubscriptions.endpoint, endpoint)).run();
  }

  deletePushSubscription(endpoint: string): boolean {
    return this.db.delete(t.pushSubscriptions).where(eq(t.pushSubscriptions.endpoint, endpoint)).run().changes > 0;
  }

  // ── APNs devices (native iOS, later) ──────────────────────

  upsertApnsDevice(token: string, environment: ApnsDevice['environment']) {
    this.db
      .insert(t.apnsDevices)
      .values({ token, environment })
      .onConflictDoUpdate({ target: t.apnsDevices.token, set: { environment } })
      .run();
  }

  listApnsDevices(): ApnsDevice[] {
    return this.db.select().from(t.apnsDevices).all();
  }

  deleteApnsDevice(token: string) {
    this.db.delete(t.apnsDevices).where(eq(t.apnsDevices.token, token)).run();
  }
}
