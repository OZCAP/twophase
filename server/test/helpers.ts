import { Client as McpClient } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { createApp } from '../src/app.js';
import { loadConfig, type Config } from '../src/config.js';
import type { Whois } from '../src/tailscaleAuth.js';

export const ADMIN = 'test-admin-token';

/** Superuser connection to the throwaway test server (see README → Development). */
export const PG_ADMIN_URL = process.env.PG_TEST_URL ?? 'postgresql://mcptest:mcptest@127.0.0.1:55432/shop';

export async function postgresAvailable(): Promise<boolean> {
  const c = new pg.Client({ connectionString: PG_ADMIN_URL, connectionTimeoutMillis: 2000 });
  try {
    await c.connect();
    return true;
  } catch {
    return false;
  } finally {
    await c.end().catch(() => {});
  }
}

/**
 * A fresh database with a small shop schema and a dedicated, non-superuser login for the proxy,
 * so tests exercise the proxy the way it should run in production.
 */
export async function createTestDatabase() {
  const suffix = randomBytes(4).toString('hex');
  const database = `proxytest_${suffix}`;
  const role = `proxy_${suffix}`;
  const password = randomBytes(12).toString('hex');
  const admin = new pg.Client({ connectionString: PG_ADMIN_URL });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${database}`);
  await admin.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`);
  await admin.end();

  const url = new URL(PG_ADMIN_URL);
  url.pathname = `/${database}`;
  const owner = new pg.Client({ connectionString: url.toString() });
  await owner.connect();
  await owner.query(`
    CREATE TABLE customers (id serial PRIMARY KEY, email text UNIQUE NOT NULL, name text NOT NULL);
    CREATE TABLE orders (id serial PRIMARY KEY, customer_id int REFERENCES customers(id), total_cents int NOT NULL, status text NOT NULL DEFAULT 'paid');
    CREATE TABLE secrets (id int PRIMARY KEY, value text);
    INSERT INTO customers (email, name) SELECT 'user' || g || '@example.com', 'Customer ' || g FROM generate_series(1, 20) g;
    INSERT INTO orders (customer_id, total_cents) SELECT 1 + g % 20, 100 * g FROM generate_series(1, 50) g;
    INSERT INTO secrets VALUES (1, 'hunter2');
    CREATE FUNCTION order_total(int) RETURNS bigint LANGUAGE sql STABLE AS $$ SELECT sum(total_cents) FROM orders WHERE customer_id = $1 $$;
    CREATE FUNCTION bump_order(int) RETURNS void LANGUAGE sql VOLATILE AS $$ UPDATE orders SET total_cents = total_cents + 1 WHERE id = $1 $$;
    GRANT CONNECT, TEMP ON DATABASE ${database} TO ${role};
    GRANT USAGE, CREATE ON SCHEMA public TO ${role};
    GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public TO ${role};
    GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO ${role};
  `);

  return {
    database,
    role,
    password,
    /** Direct (not proxied) superuser access, to check what really happened. */
    direct: owner,
    sql: async <T = any>(q: string, params?: unknown[]) => (await owner.query(q, params)).rows as T[],
    async drop() {
      await owner.end();
      const a = new pg.Client({ connectionString: PG_ADMIN_URL });
      await a.connect();
      await a.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await a.query(`DROP ROLE IF EXISTS ${role}`);
      await a.end();
    },
  };
}

export type TestDatabase = Awaited<ReturnType<typeof createTestDatabase>>;

/** Boots a proxy (HTTP + wire listener on random ports) with an in-memory store. */
export async function startProxy(overrides: Partial<Config> = {}, deps: { whois?: Whois } = {}) {
  const base0 = loadConfig({});
  const proxy = createApp(
    {
      ...base0,
      dataDir: ':memory:',
      port: 0,
      host: '127.0.0.1',
      adminToken: ADMIN,
      approvalTimeoutSeconds: 5,
      ...overrides,
      wire: { enabled: true, host: '127.0.0.1', port: 0, publicPort: 0, ...overrides.wire },
    },
    deps,
  );
  const { httpPort, wirePort } = await proxy.listen();
  const base = `http://127.0.0.1:${httpPort}`;

  async function admin<T = any>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${base}/admin/api${path}`, {
      method,
      headers: { authorization: `Bearer ${ADMIN}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`${method} ${path} → ${res.status} ${await res.text()}`);
    return (res.status === 204 ? undefined : await res.json()) as T;
  }

  async function mcp(token: string, slug: string) {
    const client = new McpClient({ name: 'test-agent', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp/${slug}`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
    return client;
  }

  /** A node-postgres client connected through the proxy's wire listener. */
  async function wire(user: string, password: string, database: string, extra: Partial<pg.ClientConfig> = {}) {
    const client = new pg.Client({ host: '127.0.0.1', port: wirePort!, user, password, database, connectionTimeoutMillis: 5000, ...extra });
    client.on('error', () => {});
    await client.connect();
    return client;
  }

  async function nextPending(): Promise<any> {
    for (let i = 0; i < 200; i++) {
      const [a] = await admin<any[]>('GET', '/approvals?status=pending');
      if (a) return a;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error('no pending approval appeared');
  }

  /** Registers a test database and one client with MCP + wire access. */
  async function seed(tdb: TestDatabase, slug = 'shop') {
    const url = new URL(PG_ADMIN_URL);
    const db = await admin('POST', '/databases', {
      slug,
      name: 'Shop',
      host: url.hostname,
      port: Number(url.port),
      database: tdb.database,
      user: tdb.role,
      password: tdb.password,
      sslmode: 'disable',
    });
    const client = await admin('POST', '/users', { name: 'agent', access: [{ databaseId: db.id, allowMcp: true, allowWire: true }] });
    return { db, client: client as { user: any; token: string } };
  }

  return {
    base,
    wirePort: wirePort!,
    admin,
    mcp,
    wire,
    nextPending,
    seed,
    approvals: proxy.approvals,
    async close() {
      await proxy.close();
    },
  };
}

export type TestProxy = Awaited<ReturnType<typeof startProxy>>;

export const textOf = (r: any) => (r.content?.[0]?.text ?? '') as string;
export const jsonOf = (r: any) => JSON.parse(textOf(r));
