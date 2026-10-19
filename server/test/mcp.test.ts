import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, jsonOf, postgresAvailable, startProxy, textOf, type TestDatabase, type TestProxy } from './helpers.js';

const available = await postgresAvailable();

describe.skipIf(!available)('hosted MCP against real Postgres', () => {
  let tdb: TestDatabase;
  let proxy: TestProxy;
  let db: any;
  let token: string;
  let agent: Awaited<ReturnType<TestProxy['mcp']>>;
  const query = (sql: string, extra: Record<string, unknown> = {}) => agent.callTool({ name: 'query', arguments: { sql, ...extra } });

  beforeAll(async () => {
    tdb = await createTestDatabase();
    proxy = await startProxy();
    ({ db, client: { token } } = (await proxy.seed(tdb)) as any);
    agent = await proxy.mcp(token, 'shop');
  });

  afterAll(async () => {
    await agent?.close();
    await proxy?.close();
    await tdb?.drop();
  });

  it('exposes query, list_tables, describe_table and explain', async () => {
    const { tools } = await agent.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['describe_table', 'explain', 'list_tables', 'query']);
  });

  it('runs reads immediately, inside a READ ONLY transaction', async () => {
    const r = jsonOf(await query('SELECT count(*) AS n FROM orders; SHOW transaction_read_only'));
    expect(r.statements[0].rows).toEqual([{ n: '50' }]);
    expect(r.statements[1].rows).toEqual([{ transaction_read_only: 'on' }]);
  });

  it('uses the catalog: STABLE functions are reads, VOLATILE ones need approval', async () => {
    expect(jsonOf(await query('SELECT order_total(1) AS t')).statements[0].rows[0].t).toBe('6000');
    const call = query('SELECT bump_order(1)');
    const pending = await proxy.nextPending();
    expect(pending.operations).toEqual(['write']);
    await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'deny' });
    expect((await call).isError).toBe(true);
  });

  it('holds a write until approved, then commits it — with a planner estimate on the card', async () => {
    const call = query("UPDATE orders SET status = 'refunded' WHERE id = 1");
    const pending = await proxy.nextPending();
    expect(pending).toMatchObject({ surface: 'mcp', operations: ['write'], tables: ['orders'], asked: [{ op: 'write', table: 'orders' }] });
    expect(pending.estimate.rows).toBe(1);
    await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'approve' });
    const r = jsonOf(await call);
    expect(r.statements[0]).toMatchObject({ command: 'UPDATE', rowCount: 1 });
    expect(await tdb.sql('SELECT status FROM orders WHERE id = 1')).toEqual([{ status: 'refunded' }]);
  });

  it('a denied write changes nothing and tells the agent not to retry', async () => {
    const call = query('DELETE FROM orders');
    const pending = await proxy.nextPending();
    await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'deny' });
    const r = await call;
    expect(r.isError).toBe(true);
    expect(textOf(r)).toMatch(/denied by the operator.*Do not retry/);
    expect(await tdb.sql('SELECT count(*)::int AS n FROM orders')).toEqual([{ n: 50 }]);
  });

  it('catches the EXPLAIN ANALYZE bypass in both query and explain', async () => {
    const call = query("EXPLAIN ANALYZE UPDATE orders SET status = 'probe' WHERE id = 2");
    const pending = await proxy.nextPending();
    expect(pending.operations).toEqual(['write']);
    await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'deny' });
    await call;
    const viaExplain = await agent.callTool({ name: 'explain', arguments: { sql: "ANALYZE UPDATE orders SET status = 'probe' WHERE id = 2" } });
    expect(viaExplain.isError).toBe(true);
    expect(await tdb.sql('SELECT status FROM orders WHERE id = 2')).toEqual([{ status: 'paid' }]);
    const plain = jsonOf(await agent.callTool({ name: 'explain', arguments: { sql: 'SELECT * FROM orders WHERE id = 2' } }));
    expect(plain.plan).toMatch(/Scan/);
  });

  it('denies admin statements by default without asking', async () => {
    const r = await query('SELECT pg_terminate_backend(pg_backend_pid())');
    expect(r.isError).toBe(true);
    expect(textOf(r)).toMatch(/admin is not permitted/);
    const unparseable = await query('SELEC oops');
    expect(textOf(unparseable)).toMatch(/could not be parsed/);
  });

  it('applies table rules: allow writes to one table, deny reads of another', async () => {
    const allow = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'write', tablePattern: 'orders', action: 'allow' });
    const deny = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'read', tablePattern: 'secrets', action: 'deny', note: 'never' });

    expect(jsonOf(await query('UPDATE orders SET total_cents = total_cents WHERE id = 3')).statements[0].rowCount).toBe(1);
    const secret = await query('SELECT * FROM secrets');
    expect(textOf(secret)).toMatch(/read on secrets is not permitted for agent \(never\)/);
    const tables = jsonOf(await agent.callTool({ name: 'list_tables', arguments: {} })).tables.map((t: any) => t.name);
    expect(tables).toEqual(['customers', 'orders']);

    await proxy.admin('DELETE', `/rules/${allow.id}`);
    await proxy.admin('DELETE', `/rules/${deny.id}`);
  });

  it('verb-level rules: inserts auto-approved, deletes still ask; trust windows stay verb-specific', async () => {
    const rule = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'insert', action: 'allow' });
    const ins = jsonOf(await query("INSERT INTO customers (email, name) VALUES ('verb@example.com', 'Verb')"));
    expect(ins.statements[0]).toMatchObject({ command: 'INSERT', rowCount: 1 });

    const del = query("DELETE FROM customers WHERE email = 'verb@example.com'");
    const pending = await proxy.nextPending();
    expect(pending).toMatchObject({ verbs: ['delete'], asked: [{ op: 'write', verb: 'delete', table: 'customers' }] });
    await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'approve', scope: 'tables', durationMinutes: 5 });
    await del;
    const [grant] = await proxy.admin<any[]>('GET', '/grants');
    expect(grant).toMatchObject({ operation: 'delete', tablePattern: 'customers' });

    // The trust window covers deletes on customers, not updates.
    const upd = query("UPDATE customers SET name = 'x' WHERE id = 2");
    const again = await proxy.nextPending();
    expect(again.verbs).toEqual(['update']);
    await proxy.admin('POST', `/approvals/${again.id}/decision`, { decision: 'deny' });
    await upd;

    const audit = await proxy.admin<any[]>('GET', '/audit?limit=5');
    expect(audit.find((a) => a.sql.startsWith('INSERT INTO customers'))).toMatchObject({ decision: 'allowed', verbs: ['insert'] });
    await proxy.admin('DELETE', `/grants/${grant.id}`);
    await proxy.admin('DELETE', `/rules/${rule.id}`);
  });

  it('runs multiple statements atomically: a failure rolls the approved write back', async () => {
    const call = query("UPDATE orders SET status = 'x' WHERE id = 4; SELECT 1/0");
    const pending = await proxy.nextPending();
    await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'approve' });
    const r = await call;
    expect(textOf(r)).toMatch(/\[22012\] division by zero/);
    expect(await tdb.sql('SELECT status FROM orders WHERE id = 4')).toEqual([{ status: 'paid' }]);
  });

  it('trust windows scoped to "these tables" skip asking for the same table only', async () => {
    const first = query("UPDATE orders SET status = 'a' WHERE id = 5");
    const pending = await proxy.nextPending();
    await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'approve', scope: 'tables', durationMinutes: 5 });
    await first;
    expect(jsonOf(await query("UPDATE orders SET status = 'b' WHERE id = 5")).statements[0].rowCount).toBe(1);

    const other = query("UPDATE customers SET name = 'x' WHERE id = 1");
    const again = await proxy.nextPending();
    expect(again.tables).toEqual(['customers']);
    await proxy.admin('POST', `/approvals/${again.id}/decision`, { decision: 'deny' });
    await other;
    for (const g of await proxy.admin<any[]>('GET', '/grants')) await proxy.admin('DELETE', `/grants/${g.id}`);
  });

  it('rejects transaction control and session-wide SET, allows SET LOCAL', async () => {
    expect(textOf(await query('BEGIN; DELETE FROM orders; COMMIT'))).toMatch(/Transaction control/);
    expect(textOf(await query('SET search_path = x'))).toMatch(/SET LOCAL/);
    const r = jsonOf(await query('SET LOCAL statement_timeout = 1234; SHOW statement_timeout'));
    expect(r.statements[1].rows[0].statement_timeout).toBe('1234ms');
  });

  it('caps rows and reports truncation; supports params', async () => {
    const r = jsonOf(await query('SELECT id FROM orders ORDER BY id', { maxRows: 3 }));
    expect(r.statements[0]).toMatchObject({ rows: [{ id: 1 }, { id: 2 }, { id: 3 }], truncated: true });
    const p = jsonOf(await query('SELECT name FROM customers WHERE id = $1', { params: [7] }));
    expect(p.statements[0].rows).toEqual([{ name: 'Customer 7' }]);
  });

  it('describe_table returns columns, indexes and foreign keys', async () => {
    const t = jsonOf(await agent.callTool({ name: 'describe_table', arguments: { table: 'orders' } }));
    expect(t.columns.map((c: any) => c.name)).toEqual(['id', 'customer_id', 'total_cents', 'status']);
    expect(t.indexes[0]).toMatchObject({ name: 'orders_pkey', primary: true });
    expect(t.foreignKeys[0].definition).toMatch(/REFERENCES customers\(id\)/);
  });

  it('audits every decision with operations, tables and row counts', async () => {
    const audit = await proxy.admin<any[]>('GET', '/audit?limit=100');
    const update = audit.find((a) => a.sql === "UPDATE orders SET status = 'refunded' WHERE id = 1");
    expect(update).toMatchObject({ surface: 'mcp', decision: 'approved', operations: ['write'], tables: ['orders'], rowCount: 1 });
    expect(audit.some((a) => a.decision === 'denied' && a.sqlstate === '42501')).toBe(true);
    expect(audit.some((a) => a.decision === 'rejected')).toBe(true);
  });

  it('reports over-privileged logins on connection test', async () => {
    const t = await proxy.admin('POST', `/databases/${db.id}/test`);
    expect(t).toMatchObject({ ok: true, user: tdb.role, warnings: [] });
  });
});
