// End to end against real Postgres: statements and batches that do several things at once.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, jsonOf, postgresAvailable, startProxy, textOf, type TestDatabase, type TestProxy } from './helpers.js';

const available = await postgresAvailable();

describe.skipIf(!available)('complex statements against real Postgres', () => {
  let tdb: TestDatabase;
  let proxy: TestProxy;
  let db: any;
  let client: { user: any; token: string };
  let agent: Awaited<ReturnType<TestProxy['mcp']>>;
  const query = (sql: string) => agent.callTool({ name: 'query', arguments: { sql } });
  const wire = () => proxy.wire(client.user.username, client.token, 'shop');
  const decideNext = async (decision: 'approve' | 'deny', extra = {}) => {
    const a = await proxy.nextPending();
    await proxy.admin('POST', `/approvals/${a.id}/decision`, { decision, ...extra });
    return a;
  };
  const count = async (where: string, table = 'orders') => (await tdb.sql(`SELECT count(*)::int AS n FROM ${table} WHERE ${where}`))[0].n as number;
  const sorted = (xs: string[]) => [...xs].sort();

  beforeAll(async () => {
    tdb = await createTestDatabase();
    await tdb.sql(`
      CREATE TABLE orders_archive (LIKE orders);
      CREATE TABLE audit_log (id serial PRIMARY KEY, action text NOT NULL, n int NOT NULL);
      GRANT SELECT, INSERT, UPDATE, DELETE ON orders_archive, audit_log TO ${tdb.role};
      GRANT USAGE ON SEQUENCE audit_log_id_seq TO ${tdb.role};
    `);
    proxy = await startProxy();
    ({ db, client } = await proxy.seed(tdb));
    agent = await proxy.mcp(client.token, 'shop');
  });

  afterAll(async () => {
    await agent?.close();
    await proxy?.close();
    await tdb?.drop();
  });

  describe('over MCP', () => {
    it('archive-and-log in one statement: the card shows all three writes, approval runs them together', async () => {
      await tdb.sql("UPDATE orders SET status = 'cancelled' WHERE id IN (40, 41, 42)");
      const call = query(`
        WITH moved AS (DELETE FROM orders WHERE status = 'cancelled' RETURNING *),
             archived AS (INSERT INTO orders_archive SELECT * FROM moved RETURNING id)
        INSERT INTO audit_log (action, n) SELECT 'archive', count(*) FROM archived RETURNING action, n`);
      const a = await decideNext('approve');
      expect(sorted(a.verbs)).toEqual(['delete', 'insert']);
      expect(sorted(a.tables)).toEqual(['audit_log', 'orders', 'orders_archive']);
      expect(sorted(a.asked.map((x: any) => `${x.verb}:${x.table}`))).toEqual(['delete:orders', 'insert:audit_log', 'insert:orders_archive']);

      expect(jsonOf(await call).statements[0].rows).toEqual([{ action: 'archive', n: 3 }]);
      expect(await count("status = 'cancelled'")).toBe(0);
      expect(await count('id IN (40, 41, 42)', 'orders_archive')).toBe(3);
    });

    it('read → write → read: one approval, and the second read sees the write', async () => {
      const call = query("SELECT status FROM orders WHERE id = 7; UPDATE orders SET status = 'shipped' WHERE id = 7; SELECT status FROM orders WHERE id = 7");
      const a = await decideNext('approve');
      expect(a.statements.map((s: any) => s.kind)).toEqual(['read', 'write', 'read']);
      const r = jsonOf(await call);
      expect(r.statements.map((s: any) => s.rows?.[0]?.status ?? s.command)).toEqual(['paid', 'UPDATE', 'shipped']);
      expect(await proxy.admin<any[]>('GET', '/approvals?status=pending')).toEqual([]);
    });

    it('a rule that allows inserts still asks for the delete in the same batch; denying it undoes the insert too', async () => {
      const rule = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'insert', action: 'allow' });
      const call = query("INSERT INTO audit_log (action, n) VALUES ('should-vanish', 1); DELETE FROM orders WHERE id = 8");
      const a = await decideNext('deny');
      expect(a.asked).toEqual([{ op: 'write', verb: 'delete', table: 'orders' }]);
      expect((await call).isError).toBe(true);
      expect(await count("action = 'should-vanish'", 'audit_log')).toBe(0);
      expect(await count('id = 8')).toBe(1);
      await proxy.admin('DELETE', `/rules/${rule.id}`);
    });

    it('a "these tables" trust window covers a repeat of the same multi-table statement, not a new table', async () => {
      const sql = "WITH d AS (DELETE FROM orders WHERE id = $ID RETURNING *) INSERT INTO orders_archive SELECT * FROM d";
      const first = query(sql.replace('$ID', '9'));
      await decideNext('approve', { scope: 'tables', durationMinutes: 5 });
      await first;
      // Same verbs on the same tables: runs straight away.
      expect(jsonOf(await query(sql.replace('$ID', '10'))).statements[0]).toMatchObject({ command: 'INSERT', rowCount: 1 });
      // Also writes audit_log, which the window doesn't cover: the whole batch asks again.
      const third = query(`${sql.replace('$ID', '11')}; INSERT INTO audit_log (action, n) VALUES ('x', 1)`);
      const a = await decideNext('deny');
      expect(a.asked).toContainEqual({ op: 'write', verb: 'insert', table: 'audit_log' });
      await third;
      expect(await count('id = 11')).toBe(1);
      for (const g of await proxy.admin<any[]>('GET', '/grants')) await proxy.admin('DELETE', `/grants/${g.id}`);
    });

    it('a denied read hidden in a subquery of a write blocks the whole statement without asking', async () => {
      const rule = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'read', tablePattern: 'secrets', action: 'deny' });
      const r = await query('UPDATE orders SET status = (SELECT value FROM secrets WHERE id = 1) WHERE id = 12');
      expect(r.isError).toBe(true);
      expect(textOf(r)).toMatch(/read on secrets is not permitted/);
      expect(await proxy.admin<any[]>('GET', '/approvals?status=pending')).toEqual([]);
      expect((await tdb.sql('SELECT status FROM orders WHERE id = 12'))[0].status).toBe('paid');
      await proxy.admin('DELETE', `/rules/${rule.id}`);
    });

    it('an admin statement at the end of a batch of reads denies the whole batch', async () => {
      const r = await query('SELECT count(*) FROM orders; SELECT count(*) FROM customers; SELECT pg_reload_conf()');
      expect(r.isError).toBe(true);
      expect(textOf(r)).toMatch(/admin is not permitted/);
    });
  });

  describe('over the wire', () => {
    it('a simple-query batch of reads and writes waits for one approval and returns every result', async () => {
      const c = await wire();
      const run = c.query(
        "SELECT count(*)::int AS n FROM audit_log; INSERT INTO audit_log (action, n) VALUES ('batch', 1); UPDATE orders SET status = 'batch' WHERE id = 13; SELECT status FROM orders WHERE id = 13",
      );
      const a = await decideNext('approve');
      expect(a.surface).toBe('wire');
      expect(sorted(a.verbs)).toEqual(['insert', 'update']);
      const results = (await run) as unknown as { command: string; rows: any[] }[];
      expect(results.map((r) => r.command)).toEqual(['SELECT', 'INSERT', 'UPDATE', 'SELECT']);
      expect(results[3].rows).toEqual([{ status: 'batch' }]);
      await c.end();
    });

    it('denying a batch runs none of it, not even the statements before the write', async () => {
      const c = await wire();
      const run = c.query("INSERT INTO audit_log (action, n) VALUES ('denied-batch', 1); DELETE FROM orders WHERE id = 14");
      await decideNext('deny');
      await expect(run).rejects.toMatchObject({ code: '42501' });
      expect(await count("action = 'denied-batch'", 'audit_log')).toBe(0);
      expect(await count('id = 14')).toBe(1);
      expect((await c.query('SELECT 1 AS ok')).rows).toEqual([{ ok: 1 }]);
      await c.end();
    });

    it('a transaction with a savepoint: each write asks, ROLLBACK TO undoes only the second', async () => {
      const c = await wire();
      await c.query('BEGIN');
      const ins = c.query("INSERT INTO audit_log (action, n) VALUES ('kept', 1)");
      await decideNext('approve');
      await ins;
      await c.query('SAVEPOINT before_update');
      const upd = c.query("UPDATE orders SET status = 'undone' WHERE id = 15");
      const a = await decideNext('approve');
      expect(a.session.transactionStatus).toBe('transaction');
      await upd;
      await c.query('ROLLBACK TO SAVEPOINT before_update');
      await c.query('COMMIT');
      expect(await count("action = 'kept'", 'audit_log')).toBe(1);
      expect((await tdb.sql('SELECT status FROM orders WHERE id = 15'))[0].status).toBe('paid');
      await c.end();
    });

    it('a denial after approved writes in a transaction aborts it: COMMIT rolls everything back', async () => {
      const c = await wire();
      await c.query('BEGIN');
      const first = c.query("UPDATE orders SET status = 'approved-then-lost' WHERE id = 16");
      await decideNext('approve');
      await first;
      const second = c.query('DELETE FROM orders WHERE id = 17');
      await decideNext('deny');
      await expect(second).rejects.toMatchObject({ code: '42501' });
      await expect(c.query('SELECT 1')).rejects.toMatchObject({ code: '25P02' }); // in failed transaction
      const commit = await c.query('COMMIT');
      expect(commit.command).toBe('ROLLBACK');
      expect((await tdb.sql('SELECT status FROM orders WHERE id = 16'))[0].status).toBe('paid');
      expect(await count('id = 17')).toBe(1);
      await c.end();
    });

    it('PREPARE and EXECUTE in one batch ask for what EXECUTE runs', async () => {
      const c = await wire();
      const run = c.query('PREPARE purge (int) AS DELETE FROM orders WHERE id = $1; EXECUTE purge(18)');
      const a = await decideNext('approve');
      expect(a.asked).toEqual([{ op: 'write', verb: 'delete', table: 'orders' }]);
      await run;
      expect(await count('id = 18')).toBe(0);
      await c.end();
    });

    it('extended protocol: a parameterised archive-and-delete CTE shows its parameters and runs once approved', async () => {
      const c = await wire();
      const run = c.query(
        'WITH d AS (DELETE FROM orders WHERE id = ANY($1::int[]) RETURNING *) INSERT INTO orders_archive SELECT * FROM d RETURNING id',
        [[19, 20]],
      );
      const a = await decideNext('approve');
      expect(a.params).toEqual(['{"19","20"}']);
      expect(sorted(a.asked.map((x: any) => `${x.verb}:${x.table}`))).toEqual(['delete:orders', 'insert:orders_archive']);
      expect((await run).rows.map((r: any) => r.id).sort()).toEqual([19, 20]);
      expect(await count('id IN (19, 20)')).toBe(0);
      await c.end();
    });

    it('a write tucked inside a read (data-modifying CTE feeding a UNION) is caught on the wire', async () => {
      const c = await wire();
      const run = c.query('WITH d AS (DELETE FROM orders WHERE id = 21 RETURNING id) SELECT id FROM customers WHERE id = 1 UNION ALL SELECT id FROM d');
      const a = await decideNext('deny');
      expect(a.asked).toEqual([{ op: 'write', verb: 'delete', table: 'orders' }]);
      await expect(run).rejects.toMatchObject({ code: '42501' });
      expect(await count('id = 21')).toBe(1);
      await c.end();
    });
  });
});
