import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { ApprovalError, type ApprovalService } from './approvals.js';
import { bearerToken, hashToken, issueClientToken, safeEqualHex, usernameFor } from './auth.js';
import type { Config } from './config.js';
import type { ExecutorRegistry } from './engines/postgres/executor.js';
import { OPERATIONS, POLICY_TARGETS } from './engines/types.js';
import { EVENT_NAMES, type EventBus } from './events.js';
import { decideAccess } from './policy.js';
import type { PushService } from './push/index.js';
import type { DatabaseConfig, DatabaseInput, Store } from './store.js';
import { isAllowed, tailnetCallerIp, type TailscaleIdentity, type Whois } from './tailscaleAuth.js';

export interface AdminDeps {
  store: Store;
  approvals: ApprovalService;
  executors: ExecutorRegistry;
  events: EventBus;
  push: PushService;
  config: Config;
  adminAuth: AdminAuth;
}

export type AdminAuth = { mode: 'token'; tokenHash: string } | { mode: 'tailscale'; allow: string[]; whois: Whois };

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}

const action = z.enum(['allow', 'approve', 'deny']);
const operation = z.enum(POLICY_TARGETS as [string, ...string[]]).transform((t) => t as (typeof POLICY_TARGETS)[number]);

const databaseFields = z.object({
  slug: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,62}$/, 'lowercase letters, digits, dashes and underscores'),
  name: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  database: z.string().min(1),
  user: z.string().min(1),
  password: z.string(),
  sslmode: z.enum(['disable', 'prefer', 'require', 'verify-full']),
  readonlyUser: z.string().min(1).nullable(),
  readonlyPassword: z.string().nullable(),
  defaultRead: action,
  defaultWrite: action,
  defaultDdl: action,
  defaultAdmin: action,
  statementTimeoutMs: z.number().int().min(100).max(3_600_000),
  maxRows: z.number().int().min(1).max(1000),
  enabled: z.boolean(),
});
const databaseCreate = databaseFields.partial().required({ slug: true, name: true, host: true, database: true, user: true });
const databasePatch = databaseFields.partial();

const accessEntry = z.object({ databaseId: z.string(), allowMcp: z.boolean().default(true), allowWire: z.boolean().default(true) });
const userCreate = z.object({ name: z.string().min(1), access: z.array(accessEntry).default([]) });
const userPatch = z.object({ name: z.string().min(1), enabled: z.boolean(), access: z.array(accessEntry) }).partial();

const tablePattern = z.string().min(1).max(200).nullable();
const ruleCreate = z.object({
  databaseId: z.string(),
  userId: z.string().nullable().default(null),
  operation,
  tablePattern: tablePattern.default(null),
  action,
  note: z.string().nullable().default(null),
});
const rulePatch = z.object({ userId: z.string().nullable(), operation, tablePattern, action, note: z.string().nullable() }).partial();

const grantCreate = z.object({
  databaseId: z.string(),
  userId: z.string().nullable().default(null),
  operation: operation.nullable().default(null),
  tablePattern: tablePattern.default(null),
  durationMinutes: z.number().positive().nullable().default(null),
  note: z.string().nullable().default(null),
});

const decision = z.object({
  decision: z.enum(['approve', 'deny']),
  scope: z.enum(['once', 'tables', 'operation', 'database']).default('once'),
  durationMinutes: z.number().positive().nullable().default(null),
});

const pushSubscription = z.object({
  // Real push services are always HTTPS; plain HTTP is only accepted on loopback (tests, local relays).
  endpoint: z
    .string()
    .url()
    .refine((u) => /^https:\/\//.test(u) || /^http:\/\/(127\.0\.0\.1|localhost)[:/]/.test(u), 'must be an https URL'),
  keys: z.object({ p256dh: z.string().min(1), auth: z.string().min(1) }),
});

const apnsDevice = z.object({ token: z.string().regex(/^[0-9a-fA-F]{32,200}$/), environment: z.enum(['sandbox', 'production']) });

function parse<T extends z.ZodType>(schema: T, body: unknown): z.output<T> {
  const r = schema.safeParse(body ?? {});
  if (!r.success) throw new HttpError(400, 'Invalid request body', z.flattenError(r.error as z.ZodError<any>));
  return r.data;
}

const intParam = (v: unknown) => (typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : undefined);
const strParam = (v: unknown) => (typeof v === 'string' && v ? v : undefined);

/** Never send stored database passwords back to the browser. */
function publicDatabase({ password, readonlyPassword, ...db }: DatabaseConfig) {
  return { ...db, hasPassword: password !== '', hasReadonlyPassword: !!readonlyPassword };
}

/**
 * Management API used by the web app: `/admin/api/*`. Authenticated by `Authorization: Bearer <admin token>`,
 * or in tailscale mode by which tailnet device the request comes from.
 */
export function adminRouter(deps: AdminDeps) {
  const { store, approvals, executors, events, push, config } = deps;
  const r = Router();

  const auth = deps.adminAuth;
  r.use(async (req, res, next) => {
    if (auth.mode === 'token') {
      const token = bearerToken(req);
      if (!token || !safeEqualHex(hashToken(token), auth.tokenHash)) {
        res.setHeader('WWW-Authenticate', 'Bearer');
        return res.status(401).json({ error: 'Invalid admin token' });
      }
      return next();
    }
    const ip = tailnetCallerIp(req);
    const identity = ip ? await auth.whois(ip).catch(() => null) : null;
    if (!identity) return res.status(401).json({ error: 'Open this through Tailscale to manage the proxy' });
    if (!isAllowed(identity, auth.allow)) return res.status(403).json({ error: `Device "${identity.node}" is not allowed to manage the proxy` });
    res.locals.identity = identity;
    next();
  });

  const withNames = <T extends { databaseId: string; userId: string | null }>(items: T[]) => {
    const dbs = new Map(store.listDatabases().map((d) => [d.id, d.name]));
    const users = new Map(store.listUsers().map((u) => [u.id, u.name]));
    return items.map((i) => ({ ...i, databaseName: dbs.get(i.databaseId) ?? null, userName: i.userId ? (users.get(i.userId) ?? null) : null }));
  };
  const mustDatabase = (id: string) => store.getDatabase(id) ?? fail(404, 'Database not found');
  const mustUser = (id: string) => store.getUser(id) ?? fail(404, 'Client not found');

  // ── status & events ─────────────────────────────────────

  r.get('/status', (_req, res) => {
    const identity = res.locals.identity as TailscaleIdentity | undefined;
    res.json({
      auth: { mode: auth.mode, device: identity?.node ?? null, login: identity?.login ?? null },
      version: '0.2.0',
      wire: { enabled: config.wire.enabled, port: config.wire.publicPort },
      apnsEnabled: push.apnsEnabled,
      webPushSubscriptions: store.listPushSubscriptions().length,
      approvalTimeoutSeconds: config.approvalTimeoutSeconds,
      pendingApprovals: store.listApprovals({ status: 'pending' }).length,
    });
  });

  r.get('/events', (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    const send = (event: string, data: unknown) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    send('ready', {});
    const offs = EVENT_NAMES.map((name) => events.on(name, (payload: any) => send(name, 'databaseId' in payload ? withNames([payload])[0] : payload)));
    const ping = setInterval(() => res.write(': ping\n\n'), 20_000);
    req.on('close', () => {
      clearInterval(ping);
      offs.forEach((off) => off());
    });
  });

  // ── databases ───────────────────────────────────────────

  r.get('/databases', (_req, res) => {
    res.json(store.listDatabases().map(publicDatabase));
  });

  r.post('/databases', (req, res) => {
    const body = parse(databaseCreate, req.body);
    if (store.getDatabaseBySlug(body.slug)) throw new HttpError(409, 'Slug already in use');
    const input: DatabaseInput = { port: 5432, ...body };
    res.status(201).json(publicDatabase(store.createDatabase(input)));
  });

  r.get('/databases/:id', (req, res) => {
    res.json(publicDatabase(mustDatabase(req.params.id)));
  });

  r.patch('/databases/:id', async (req, res) => {
    const current = mustDatabase(req.params.id);
    const patch = parse(databasePatch, req.body);
    if (patch.slug && patch.slug !== current.slug && store.getDatabaseBySlug(patch.slug)) throw new HttpError(409, 'Slug already in use');
    res.json(publicDatabase(store.updateDatabase(current.id, patch)!));
  });

  r.delete('/databases/:id', async (req, res) => {
    mustDatabase(req.params.id);
    await executors.drop(req.params.id);
    store.deleteDatabase(req.params.id);
    res.status(204).end();
  });

  /** Connects with the stored credentials and warns about an over-privileged login. */
  r.post('/databases/:id/test', async (req, res) => {
    const db = mustDatabase(req.params.id);
    try {
      res.json({ ok: true, ...(await executors.get(db).test()) });
    } catch (err) {
      res.json({ ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  });

  /** Tables with the everyone-baseline action per operation (or a client's, with ?userId=). */
  r.get('/databases/:id/tables', async (req, res) => {
    const db = mustDatabase(req.params.id);
    const userId = strParam(req.query.userId) ?? null;
    let tables;
    try {
      tables = await executors.get(db).listTables();
    } catch (err) {
      throw new HttpError(502, `Database unavailable: ${err instanceof Error ? err.message : err}`);
    }
    const rules = store.listRules({ databaseId: db.id });
    res.json(
      tables.map((t) => ({
        ...t,
        actions: Object.fromEntries(
          (['read', 'write', 'ddl'] as const).map((op) => [op, decideAccess(rules, db, userId, { op, verb: op === 'read' ? 'select' : op === 'write' ? 'update' : 'alter', table: `${t.schema}.${t.name}` }).action]),
        ),
      })),
    );
  });

  // ── clients ─────────────────────────────────────────────

  const checkAccess = (access: { databaseId: string }[]) => access.forEach((a) => mustDatabase(a.databaseId));

  r.get('/users', (_req, res) => {
    res.json(store.listUsers());
  });

  r.post('/users', (req, res) => {
    const body = parse(userCreate, req.body);
    checkAccess(body.access);
    const { token, stored } = issueClientToken();
    const username = usernameFor(body.name, (u) => store.usernameTaken(u));
    res.status(201).json({ user: store.createUser({ name: body.name, username, ...stored }, body.access), token });
  });

  r.patch('/users/:id', (req, res) => {
    mustUser(req.params.id);
    const patch = parse(userPatch, req.body);
    if (patch.access) checkAccess(patch.access);
    res.json(store.updateUser(req.params.id, patch));
  });

  r.post('/users/:id/rotate-token', (req, res) => {
    mustUser(req.params.id);
    const { token, stored } = issueClientToken();
    store.setUserToken(req.params.id, stored);
    res.json({ user: store.getUser(req.params.id), token });
  });

  r.delete('/users/:id', (req, res) => {
    mustUser(req.params.id);
    store.deleteUser(req.params.id);
    res.status(204).end();
  });

  // ── rules ───────────────────────────────────────────────

  r.get('/rules', (req, res) => {
    res.json(withNames(store.listRules({ databaseId: strParam(req.query.databaseId), userId: strParam(req.query.userId) })));
  });

  r.post('/rules', (req, res) => {
    const body = parse(ruleCreate, req.body);
    mustDatabase(body.databaseId);
    if (body.userId) mustUser(body.userId);
    res.status(201).json(withNames([store.createRule(body)])[0]);
  });

  r.patch('/rules/:id', (req, res) => {
    const patch = parse(rulePatch, req.body);
    if (patch.userId) mustUser(patch.userId);
    const rule = store.updateRule(req.params.id, patch) ?? fail(404, 'Rule not found');
    res.json(withNames([rule])[0]);
  });

  r.delete('/rules/:id', (req, res) => {
    if (!store.deleteRule(req.params.id)) throw new HttpError(404, 'Rule not found');
    res.status(204).end();
  });

  // ── grants (trust windows) ──────────────────────────────

  r.get('/grants', (_req, res) => {
    res.json(withNames(store.listActiveGrants()));
  });

  r.post('/grants', (req, res) => {
    const body = parse(grantCreate, req.body);
    mustDatabase(body.databaseId);
    if (body.userId) mustUser(body.userId);
    const grant = approvals.createGrant({
      databaseId: body.databaseId,
      userId: body.userId,
      operation: body.operation,
      tablePattern: body.tablePattern,
      expiresAt: body.durationMinutes ? new Date(Date.now() + body.durationMinutes * 60_000) : null,
      note: body.note,
    });
    res.status(201).json(withNames([grant])[0]);
  });

  r.delete('/grants/:id', (req, res) => {
    if (!approvals.revokeGrant(req.params.id)) throw new HttpError(404, 'Grant not found');
    res.status(204).end();
  });

  // ── approvals ───────────────────────────────────────────

  r.get('/approvals', (req, res) => {
    const status = strParam(req.query.status) as any;
    res.json(withNames(store.listApprovals({ status, limit: intParam(req.query.limit) })));
  });

  r.get('/approvals/:id', (req, res) => {
    res.json(withNames([store.getApproval(req.params.id) ?? fail(404, 'Approval not found')])[0]);
  });

  r.post('/approvals/:id/decision', (req, res) => {
    res.json(withNames([approvals.decide(req.params.id, parse(decision, req.body))])[0]);
  });

  // ── audit ───────────────────────────────────────────────

  r.get('/audit', (req, res) => {
    res.json(
      withNames(
        store.listAudit({
          limit: Math.min(intParam(req.query.limit) ?? 100, 500),
          beforeId: intParam(req.query.before),
          databaseId: strParam(req.query.databaseId),
          userId: strParam(req.query.userId),
        }),
      ),
    );
  });

  // ── Web Push (PWA) ──────────────────────────────────────

  r.get('/push/config', (_req, res) => {
    res.json({ vapidPublicKey: push.web.publicKey });
  });

  /** Body is the browser's `PushSubscription.toJSON()`. */
  r.post('/push/subscriptions', (req, res) => {
    const body = parse(pushSubscription, req.body);
    store.upsertPushSubscription({ endpoint: body.endpoint, p256dh: body.keys.p256dh, auth: body.keys.auth, userAgent: req.header('user-agent') ?? null });
    res.status(204).end();
  });

  r.delete('/push/subscriptions', (req, res) => {
    store.deletePushSubscription(strParam(req.query.endpoint) ?? fail(400, 'endpoint query parameter required'));
    res.status(204).end();
  });

  r.post('/push/test', async (_req, res) => {
    res.json(await push.sendTest());
  });

  // ── APNs devices (native iOS app, later) ────────────────

  r.post('/devices', (req, res) => {
    const body = parse(apnsDevice, req.body);
    store.upsertApnsDevice(body.token, body.environment);
    res.status(204).end();
  });

  r.delete('/devices/:token', (req, res) => {
    store.deleteApnsDevice(req.params.token);
    res.status(204).end();
  });

  r.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message, details: err.details });
    if (err instanceof ApprovalError) return res.status(err.status).json({ error: err.message });
    console.error('[admin]', err);
    res.status(500).json({ error: err instanceof Error ? err.message : 'Internal error' });
  });

  return r;
}

function fail(status: number, message: string): never {
  throw new HttpError(status, message);
}
