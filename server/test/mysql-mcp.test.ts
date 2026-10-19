import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { jsonOf, startProxy, textOf, type TestProxy } from './helpers.js';
import { MysqlExecutor } from '../src/engines/mysql/executor.js';
import { createMysqlTestDatabase, mysqlAvailable, seedMysql, type Flavour, type MysqlTestDatabase } from './mysql-helpers.js';

const flavours = (['mysql', 'mariadb'] as Flavour[]).filter(Boolean);
const available = Object.fromEntries(await Promise.all(flavours.map(async (f) => [f, await mysqlAvailable(f)] as const)));

describe.each(flavours)('hosted MCP against real %s', (flavour) => {
  describe.skipIf(!available[flavour])(flavour, () => {
    let tdb: MysqlTestDatabase;
    let proxy: TestProxy;
    let db: any;
    let agent: Awaited<ReturnType<TestProxy['mcp']>>;
    const query = (sql: string, extra: Record<string, unknown> = {}) => agent.callTool({ name: 'query', arguments: { sql, ...extra } });

    beforeAll(async () => {
      tdb = await createMysqlTestDatabase(flavour);
      proxy = await startProxy();
      const seeded = await seedMysql(proxy, tdb);
      db = seeded.db;
      agent = await proxy.mcp(seeded.client.token, 'shop');
    });

    afterAll(async () => {
      await agent?.close();
      await proxy?.close();
      await tdb?.drop();
    });

    it('describes itself as this engine and uses ? placeholders', async () => {
      const { tools } = await agent.listTools();
      expect(tools.find((t) => t.name === 'query')?.description).toMatch(/\?, \?/);
      expect(agent.getInstructions()).toMatch(flavour === 'mysql' ? /MySQL database/ : /MariaDB database/);
    });

    it('runs reads immediately', async () => {
      const r = jsonOf(await query('SELECT COUNT(*) AS n FROM orders; SELECT name FROM customers WHERE id = 1'));
      expect(r.statements[0].rows).toEqual([{ n: '50' }]);
      expect(r.statements[1].rows).toEqual([{ name: 'Customer 1' }]);
    });

    it('reads run in a READ ONLY transaction: the server refuses a write the classifier missed', async () => {
      const exec = new MysqlExecutor({ ...db, password: tdb.password });
      const smuggled = { text: 'UPDATE orders SET status = 1', command: 'SELECT', kind: 'read' as const, accesses: [], flags: [] };
      await expect(exec.run([smuggled], { readOnly: true, maxRows: 10 })).rejects.toThrow(/READ ONLY transaction/);
      await exec.close();
    });

    it('stored functions need approval, even ones declared READS SQL DATA', async () => {
      const call = query('SELECT order_total(1) AS t');
      const pending = await proxy.nextPending();
      expect(pending.verbs).toEqual(['function']);
      await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'approve' });
      expect(jsonOf(await call).statements[0].rows[0].t).toBe('6000');
    });

    it('holds a write until approved, then commits it — with a planner estimate', async () => {
      const call = query("UPDATE orders SET status = 'refunded' WHERE id = 1");
      const pending = await proxy.nextPending();
      expect(pending).toMatchObject({ surface: 'mcp', operations: ['write'], verbs: ['update'], tables: ['orders'] });
      expect(pending.estimate.rows).toBe(1);
      await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'approve' });
      expect(jsonOf(await call).statements[0]).toMatchObject({ command: 'UPDATE', rowCount: 1 });
      expect(await tdb.sql(`SELECT status FROM ${tdb.database}.orders WHERE id = 1`)).toEqual([{ status: 'refunded' }]);
    });

    it('a denied write changes nothing', async () => {
      const call = query('DELETE FROM orders');
      const pending = await proxy.nextPending();
      expect(pending.statements[0].flags).toContain('no_where');
      await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'deny' });
      expect(textOf(await call)).toMatch(/denied by the operator.*Do not retry/);
      expect(await tdb.sql(`SELECT COUNT(*) AS n FROM ${tdb.database}.orders`)).toEqual([{ n: 50 }]);
    });

    it('EXPLAIN ANALYZE asks like the statement it runs; the explain tool refuses it', async () => {
      const sql = flavour === 'mysql' ? 'EXPLAIN ANALYZE SELECT * FROM orders FOR UPDATE' : 'ANALYZE DELETE FROM orders WHERE id = 2';
      const call = query(sql);
      const pending = await proxy.nextPending();
      expect(pending.operations).toEqual(['write']);
      await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'deny' });
      await call;
      const viaExplain = await agent.callTool({ name: 'explain', arguments: { sql: 'ANALYZE SELECT * FROM orders' } });
      expect(viaExplain.isError).toBe(true);
      const plain = jsonOf(await agent.callTool({ name: 'explain', arguments: { sql: "SELECT * FROM orders WHERE status = 'paid'" } }));
      expect(plain.plan).toMatch(/orders/);
    });

    it('denies admin statements by default without asking', async () => {
      expect(textOf(await query("SELECT LOAD_FILE('/etc/passwd')"))).toMatch(/admin is not permitted/);
      expect(textOf(await query('SET GLOBAL max_connections = 1'))).toMatch(/admin is not permitted/);
      expect(textOf(await query("SELECT 'oops"))).toMatch(/could not be parsed/);
    });

    it('applies table rules (case-insensitively for MySQL table names)', async () => {
      const allow = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'write', tablePattern: 'Orders', action: 'allow' });
      const deny = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'read', tablePattern: 'secrets', action: 'deny', note: 'never' });
      expect(allow.tablePattern).toBe('orders');
      expect(jsonOf(await query('UPDATE orders SET total_cents = total_cents + 0 WHERE id = 3')).statements[0].command).toBe('UPDATE');
      expect(textOf(await query(`SELECT * FROM ${tdb.database}.SECRETS`))).toMatch(/read on secrets is not permitted for agent \(never\)/);
      const tables = jsonOf(await agent.callTool({ name: 'list_tables', arguments: {} })).tables.map((t: any) => t.name);
      expect(tables).toEqual(['customers', 'orders']);
      await proxy.admin('DELETE', `/rules/${allow.id}`);
      await proxy.admin('DELETE', `/rules/${deny.id}`);
    });

    it('verb rules: INSERT allowed, REPLACE still asks (it can delete)', async () => {
      const rule = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'insert', action: 'allow' });
      const ins = jsonOf(await query("INSERT INTO customers (email, name) VALUES ('verb@example.com', 'Verb')"));
      expect(ins.statements[0]).toMatchObject({ command: 'INSERT', rowCount: 1 });
      const rep = query("REPLACE INTO customers (id, email, name) VALUES (21, 'verb@example.com', 'Again')");
      const pending = await proxy.nextPending();
      expect(pending.verbs).toEqual(['delete']);
      await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'deny' });
      await rep;
      await proxy.admin('DELETE', `/rules/${rule.id}`);
    });

    it('multiple statements commit together or not at all', async () => {
      const call = query("UPDATE orders SET status = 'x' WHERE id = 4; INSERT INTO nope VALUES (1)");
      const pending = await proxy.nextPending();
      await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'approve' });
      expect(textOf(await call)).toMatch(/\[42S02\].*nope/);
      expect(await tdb.sql(`SELECT status FROM ${tdb.database}.orders WHERE id = 4`)).toEqual([{ status: 'paid' }]);
    });

    it('rejects transaction control, SET and USE', async () => {
      expect(textOf(await query('START TRANSACTION; DELETE FROM orders; COMMIT'))).toMatch(/Transaction control/);
      expect(textOf(await query('SET autocommit = 0'))).toMatch(/not available|SET/);
      expect(textOf(await query('USE shop'))).toMatch(/not available over MCP/);
    });

    it('caps rows, reports truncation, supports ? params', async () => {
      const r = jsonOf(await query('SELECT id FROM orders ORDER BY id', { maxRows: 3 }));
      expect(r.statements[0]).toMatchObject({ rows: [{ id: 1 }, { id: 2 }, { id: 3 }], truncated: true, rowCount: 50 });
      const p = jsonOf(await query('SELECT name FROM customers WHERE id = ?', { params: [7] }));
      expect(p.statements[0].rows).toEqual([{ name: 'Customer 7' }]);
      expect(p.statements[0].columns).toEqual([{ name: 'name', type: 'varchar' }]);
    });

    it('describe_table returns columns, indexes and foreign keys', async () => {
      const t = jsonOf(await agent.callTool({ name: 'describe_table', arguments: { table: 'orders' } }));
      expect(t.columns.map((c: any) => c.name)).toEqual(['id', 'customer_id', 'total_cents', 'status']);
      expect(t.indexes[0]).toMatchObject({ name: 'PRIMARY', primary: true, unique: true });
      expect(t.foreignKeys[0].definition).toMatch(/REFERENCES customers\(id\)/);
      const c = jsonOf(await agent.callTool({ name: 'list_tables', arguments: {} })).tables.find((x: any) => x.name === 'customers');
      expect(c).toMatchObject({ kind: 'table', comment: 'People who buy things' });
    });

    it('stops runaway statements at the statement timeout', async () => {
      await proxy.admin('PATCH', `/databases/${db.id}`, { statementTimeoutMs: 500 });
      const started = Date.now();
      const r = await query('SELECT SLEEP(5) AS s FROM orders LIMIT 1');
      expect(Date.now() - started).toBeLessThan(4000);
      // MySQL's max_execution_time interrupts SLEEP() by returning 1; MariaDB errors.
      if (!r.isError) expect(jsonOf(r).statements[0].rows[0].s).toBe('1');
      await proxy.admin('PATCH', `/databases/${db.id}`, { statementTimeoutMs: 30_000 });
    });

    it('the connection test has no warnings for a least-privilege login', async () => {
      const t = await proxy.admin('POST', `/databases/${db.id}/test`);
      expect(t).toMatchObject({ ok: true, warnings: [] });
      expect(t.serverVersion).toMatch(flavour === 'mariadb' ? /MariaDB/ : /^8\./);
    });

    it('audits with verbs, tables and row counts', async () => {
      const audit = await proxy.admin<any[]>('GET', '/audit?limit=100');
      expect(audit.find((a) => a.sql === "UPDATE orders SET status = 'refunded' WHERE id = 1")).toMatchObject({
        surface: 'mcp',
        decision: 'approved',
        verbs: ['update'],
        tables: ['orders'],
        rowCount: 1,
      });
    });
  });
});
