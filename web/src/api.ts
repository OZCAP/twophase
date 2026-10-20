export type Action = 'allow' | 'approve' | 'deny';
export type Operation = 'read' | 'write' | 'ddl' | 'admin';
export const OPERATIONS: Operation[] = ['read', 'write', 'ddl', 'admin'];

/** The specific statement kinds within each operation (mirrors the server's engines/types.ts). */
export const VERBS = {
  read: ['select'],
  write: ['insert', 'update', 'delete', 'merge', 'truncate', 'lock', 'function', 'call', 'notify', 'refresh'],
  ddl: ['create', 'alter', 'drop'],
  admin: ['admin'],
} as const;
export type Verb = (typeof VERBS)[Operation][number];
/** What a rule or trust window targets: a whole operation, or one verb within it. */
export type PolicyTarget = Operation | Verb;
export const targetOperation = (t: PolicyTarget): Operation =>
  (OPERATIONS as string[]).includes(t) ? (t as Operation) : OPERATIONS.find((op) => (VERBS[op] as readonly string[]).includes(t))!;
export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'cancelled';
export type Surface = 'mcp' | 'wire';

interface Named {
  databaseName: string | null;
  userName: string | null;
}

export type Engine = 'postgres' | 'mysql' | 'mariadb';
export const ENGINES: Engine[] = ['postgres', 'mysql', 'mariadb'];
export const ENGINE_LABEL: Record<Engine, string> = { postgres: 'Postgres', mysql: 'MySQL', mariadb: 'MariaDB' };
export const DEFAULT_PORT: Record<Engine, number> = { postgres: 5432, mysql: 3306, mariadb: 3306 };
/** MySQL and MariaDB share a wire protocol (and a listener). */
export const isMysql = (engine: Engine) => engine !== 'postgres';

export interface Database {
  id: string;
  slug: string;
  name: string;
  engine: Engine;
  host: string;
  port: number;
  database: string;
  user: string;
  hasPassword: boolean;
  sslmode: 'disable' | 'prefer' | 'require' | 'verify-full';
  readonlyUser: string | null;
  hasReadonlyPassword: boolean;
  defaultRead: Action;
  defaultWrite: Action;
  defaultDdl: Action;
  defaultAdmin: Action;
  statementTimeoutMs: number;
  maxRows: number;
  enabled: boolean;
  createdAt: string;
}

/** Fields for create/update. Passwords are write-only: omit to leave unchanged. */
export type DatabaseDraft = Omit<Database, 'id' | 'createdAt' | 'hasPassword' | 'hasReadonlyPassword'> & {
  password?: string;
  readonlyPassword?: string | null;
};

export const defaultKey = (op: Operation) => (`default${op[0].toUpperCase()}${op.slice(1)}` as 'defaultRead' | 'defaultWrite' | 'defaultDdl' | 'defaultAdmin');

export interface TableInfo {
  schema: string;
  name: string;
  kind: string;
  estimatedRows: number | null;
  comment: string | null;
  actions: Record<'read' | 'write' | 'ddl', Action>;
}

export interface ConnectionTest {
  ok: boolean;
  serverVersion?: string;
  user?: string;
  warnings?: string[];
  error?: string;
}

export interface DatabaseAccess {
  databaseId: string;
  allowMcp: boolean;
  allowWire: boolean;
}

export interface ProxyUser {
  id: string;
  name: string;
  username: string;
  tokenPrefix: string;
  enabled: boolean;
  access: DatabaseAccess[];
  /** False for clients from before MySQL support until their token is used over MCP or rotated. */
  mysqlLogin: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface IssuedToken {
  user: ProxyUser;
  token: string;
}

export interface Rule extends Named {
  id: string;
  databaseId: string;
  userId: string | null;
  operation: PolicyTarget;
  tablePattern: string | null;
  action: Action;
  note: string | null;
  createdAt: string;
}

export interface Grant extends Named {
  id: string;
  databaseId: string;
  userId: string | null;
  operation: PolicyTarget | null;
  tablePattern: string | null;
  expiresAt: string | null;
  approvalId: string | null;
  note: string | null;
  createdAt: string;
}

export interface Access {
  op: Operation;
  /** Missing on approvals recorded before verbs existed. */
  verb?: Verb;
  table: string | null;
}

export interface StatementAnalysis {
  text: string;
  command: string;
  kind: Operation | 'session';
  accesses: Access[];
  flags: string[];
}

export interface Approval extends Named {
  id: string;
  databaseId: string;
  userId: string;
  surface: Surface;
  sql: string;
  params: (string | null)[] | null;
  statements: StatementAnalysis[];
  asked: Access[];
  /** What a trust window already covered when the request came in (missing on older approvals). */
  trusted?: (Access & { grantId: string })[];
  operations: Operation[];
  verbs: Verb[];
  tables: string[];
  estimate: { rows: number | null; plan: string | null; error: string | null } | null;
  session: { applicationName?: string | null; transactionStatus?: 'idle' | 'transaction' | 'failed'; transactionAgeMs?: number | null } | null;
  status: ApprovalStatus;
  createdAt: string;
  expiresAt: string;
  decidedAt: string | null;
  grantId: string | null;
}

export interface AuditEntry extends Named {
  id: number;
  ts: string;
  databaseId: string;
  userId: string;
  surface: Surface;
  sql: string;
  operations: Operation[];
  verbs: Verb[];
  tables: string[];
  decision: 'allowed' | 'granted' | 'approved' | 'denied' | 'rejected' | 'expired' | 'cancelled';
  ruleId: string | null;
  approvalId: string | null;
  rowCount: number | null;
  sqlstate: string | null;
  error: string | null;
  durationMs: number | null;
}

export interface ProxyStatus {
  /** `tailscale`: no token; the server identified this device via `tailscale serve`. */
  auth: { mode: 'token' | 'tailscale'; device: string | null; login: string | null };
  version: string;
  wire: { enabled: boolean; port: number };
  mysqlWire: { enabled: boolean; port: number };
  webPushSubscriptions: number;
  approvalTimeoutSeconds: number;
  pendingApprovals: number;
}

export type DecisionScope = 'once' | 'tables' | 'operation' | 'database';
export type Decision = { decision: 'deny' } | { decision: 'approve'; scope?: DecisionScope; durationMinutes?: number | null };

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const BASE = '/admin/api';

/**
 * Client for the proxy's admin API. Same-origin: Vite proxies it in dev, the server hosts this app in prod.
 * An empty token means the server authenticates this device through Tailscale instead.
 */
export class Api {
  constructor(readonly token: string) {}

  private get authHeader(): Record<string, string> {
    return this.token ? { authorization: `Bearer ${this.token}` } : {};
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${BASE}${path}`, {
      method,
      headers: {
        ...this.authHeader,
        ...(body !== undefined && { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      const details = err?.details?.fieldErrors
        ? Object.entries(err.details.fieldErrors as Record<string, string[]>)
            .map(([k, v]) => `${k}: ${v.join(', ')}`)
            .join('; ')
        : '';
      throw new ApiError(res.status, [err?.error ?? res.statusText, details].filter(Boolean).join(' — '));
    }
    return (res.status === 204 ? undefined : await res.json()) as T;
  }

  status = () => this.request<ProxyStatus>('GET', '/status');

  databases = () => this.request<Database[]>('GET', '/databases');
  createDatabase = (d: Partial<DatabaseDraft>) => this.request<Database>('POST', '/databases', d);
  updateDatabase = (id: string, d: Partial<DatabaseDraft>) => this.request<Database>('PATCH', `/databases/${id}`, d);
  deleteDatabase = (id: string) => this.request<void>('DELETE', `/databases/${id}`);
  testDatabase = (id: string) => this.request<ConnectionTest>('POST', `/databases/${id}/test`);
  tables = (id: string, userId?: string) => this.request<TableInfo[]>('GET', `/databases/${id}/tables${userId ? `?userId=${encodeURIComponent(userId)}` : ''}`);

  users = () => this.request<ProxyUser[]>('GET', '/users');
  createUser = (name: string, access: DatabaseAccess[]) => this.request<IssuedToken>('POST', '/users', { name, access });
  updateUser = (id: string, patch: Partial<Pick<ProxyUser, 'name' | 'enabled' | 'access'>>) => this.request<ProxyUser>('PATCH', `/users/${id}`, patch);
  rotateToken = (id: string) => this.request<IssuedToken>('POST', `/users/${id}/rotate-token`);
  deleteUser = (id: string) => this.request<void>('DELETE', `/users/${id}`);

  rules = (databaseId?: string) => this.request<Rule[]>('GET', `/rules${databaseId ? `?databaseId=${databaseId}` : ''}`);
  createRule = (r: Pick<Rule, 'databaseId' | 'userId' | 'operation' | 'tablePattern' | 'action' | 'note'>) => this.request<Rule>('POST', '/rules', r);
  updateRule = (id: string, r: Partial<Pick<Rule, 'userId' | 'operation' | 'tablePattern' | 'action' | 'note'>>) => this.request<Rule>('PATCH', `/rules/${id}`, r);
  deleteRule = (id: string) => this.request<void>('DELETE', `/rules/${id}`);

  grants = () => this.request<Grant[]>('GET', '/grants');
  createGrant = (g: { databaseId: string; userId: string | null; operation: PolicyTarget | null; tablePattern: string | null; durationMinutes: number | null }) =>
    this.request<Grant>('POST', '/grants', g);
  revokeGrant = (id: string) => this.request<void>('DELETE', `/grants/${id}`);

  approvals = (status?: ApprovalStatus, limit = 50) => this.request<Approval[]>('GET', `/approvals?limit=${limit}${status ? `&status=${status}` : ''}`);
  approval = (id: string) => this.request<Approval>('GET', `/approvals/${id}`);
  decide = (id: string, d: Decision) => this.request<Approval>('POST', `/approvals/${id}/decision`, d);

  pushConfig = () => this.request<{ vapidPublicKey: string }>('GET', '/push/config');
  savePushSubscription = (sub: PushSubscriptionJSON) => this.request<void>('POST', '/push/subscriptions', sub);
  deletePushSubscription = (endpoint: string) => this.request<void>('DELETE', `/push/subscriptions?endpoint=${encodeURIComponent(endpoint)}`);
  testPush = () => this.request<{ sent: number; failed: number; removed: number }>('POST', '/push/test');

  audit = (before?: number, limit = 50) => this.request<AuditEntry[]>('GET', `/audit?limit=${limit}${before ? `&before=${before}` : ''}`);

  /**
   * Reads `/admin/api/events` (SSE). Uses fetch rather than EventSource so the auth header
   * can be sent. Resolves when the stream ends; rejects on connection errors.
   */
  async streamEvents(onEvent: (name: string, data: any) => void, signal: AbortSignal): Promise<void> {
    const res = await fetch(`${BASE}/events`, {
      headers: { ...this.authHeader, accept: 'text/event-stream' },
      signal,
    });
    if (!res.ok || !res.body) throw new ApiError(res.status, 'Event stream failed');
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      buffer += value;
      let sep;
      while ((sep = buffer.indexOf('\n\n')) !== -1) {
        const block = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        let name = 'message';
        const data: string[] = [];
        for (const line of block.split('\n')) {
          if (line.startsWith('event:')) name = line.slice(6).trim();
          else if (line.startsWith('data:')) data.push(line.slice(5).trim());
        }
        if (data.length) onEvent(name, JSON.parse(data.join('\n')));
      }
    }
  }
}

export function previewSql(sql: string, max = 140): string {
  const text = sql.replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** Host clients should use: the page's own host (that's what's reachable, e.g. over Tailscale). */
export const proxyHost = () => location.hostname;

export function psqlUrl(username: string, token: string, slug: string, port: number) {
  return `postgresql://${encodeURIComponent(username)}:${encodeURIComponent(token)}@${proxyHost()}:${port}/${slug}?sslmode=disable`;
}

export function mysqlUrl(username: string, token: string, slug: string, port: number) {
  return `mysql://${encodeURIComponent(username)}:${encodeURIComponent(token)}@${proxyHost()}:${port}/${slug}`;
}

/** The proxy's listener port for a database's wire protocol. */
export const wirePort = (status: ProxyStatus | null, engine: Engine) => (isMysql(engine) ? (status?.mysqlWire?.port ?? 3307) : (status?.wire.port ?? 6432));
export const wireEnabled = (status: ProxyStatus | null, engine: Engine) => !!(isMysql(engine) ? status?.mysqlWire?.enabled : status?.wire.enabled);
