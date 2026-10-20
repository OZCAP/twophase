// End to end against real MySQL and MariaDB: statements and batches that do several things at once.
import mysql from 'mysql2/promise';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { jsonOf, startProxy, textOf, type TestProxy } from './helpers.js';
import { createMysqlTestDatabase, mysqlAvailable, seedMysql, type Flavour, type MysqlTestDatabase } from './mysql-helpers.js';

const flavours: Flavour[] = ['mysql', 'mariadb'];
const available = Object.fromEntries(await Promise.all(flavours.map(async (f) => [f, await mysqlAvailable(f)] as const)));

describe.each(flavours)('complex statements against real %s', (flavour) => {
  describe.skipIf(!available[flavour])(flavour, () => {
    let tdb: MysqlTestDatabase;
    let proxy: TestProxy;
    let db: any;
    let user: any;
    let token: string;
    let agent: Awaited<ReturnType<TestProxy['mcp']>>;
    let c: mysql.Connection;
    const query = (sql: string) => agent.callTool({ name: 'query', arguments: { sql } });
    const decide = async (decision: 'approve' | 'deny', extra: Record<string, unknown> = {}) => {
      const pending = await proxy.nextPending();
      await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision, ...extra });
      return pending;
    };
    const direct = (q: string) => tdb.sql(q.replaceAll('{db}', tdb.database));
    const count = async (where: string, table = 'orders') => Number((await direct(`SELECT COUNT(*) AS n FROM {db}.${table} WHERE ${where}`))[0].n);
    const asked = (a: any) => a.asked.map((x: any) => `${x.verb}:${x.table}`).sort();

    beforeAll(async () => {
      tdb = await createMysqlTestDatabase(flavour);
      await direct(`CREATE TABLE {db}.customer_totals (customer_id INT PRIMARY KEY, total BIGINT NOT NULL)`);
      await direct(`CREATE TABLE {db}.audit_log (id INT AUTO_INCREMENT PRIMARY KEY, action VARCHAR(50) NOT NULL)`);
      proxy = await startProxy();
      const seeded = await seedMysql(proxy, tdb);
      db = seeded.db;
      ({ user, token } = seeded.client);
      agent = await proxy.mcp(token, 'shop');
      c = await mysql.createConnection({ host: '127.0.0.1', port: proxy.mysqlWirePort, user: user.username, password: token, database: 'shop', multipleStatements: true });
    });

    afterAll(async () => {
      await c?.end();
      await agent?.close();
      await proxy?.close();
      await tdb?.drop();
    });

    it('MCP: read → write → read in one call, one approval, the last read sees the write', async () => {
      const call = query("SELECT status FROM orders WHERE id = 7; UPDATE orders SET status = 'shipped' WHERE id = 7; SELECT status FROM orders WHERE id = 7");
      const a = await decide('approve');
      expect(a.statements.map((s: any) => s.kind)).toEqual(['read', 'write', 'read']);
      const r = jsonOf(await call);
      expect([r.statements[0].rows[0].status, r.statements[2].rows[0].status]).toEqual(['paid', 'shipped']);
    });

    it('MCP: inserts allowed by rule, the delete in the same call still asks; denying it undoes the insert', async () => {
      const rule = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'insert', action: 'allow' });
      const call = query("INSERT INTO audit_log (action) VALUES ('should-vanish'); DELETE FROM orders WHERE id = 8");
      const a = await decide('deny');
      expect(asked(a)).toEqual(['delete:orders']);
      expect((await call).isError).toBe(true);
      expect(await count("action = 'should-vanish'", 'audit_log')).toBe(0);
      expect(await count('id = 8')).toBe(1);
      await proxy.admin('DELETE', `/rules/${rule.id}`);
    });

    it('MCP: an upsert from a join asks for insert and update on the target and reads the sources', async () => {
      const call = query(`
        INSERT INTO customer_totals (customer_id, total)
        SELECT c.id, SUM(o.total_cents) FROM customers c JOIN orders o ON o.customer_id = c.id WHERE c.id <= 3 GROUP BY c.id
        ON DUPLICATE KEY UPDATE total = VALUES(total)`);
      const a = await decide('approve');
      expect(asked(a)).toEqual(['insert:customer_totals', 'update:customer_totals']);
      expect([...a.tables].sort()).toEqual(['customer_totals', 'customers', 'orders']);
      expect(jsonOf(await call).statements[0].rowCount).toBe(3);
      expect(await count('1 = 1', 'customer_totals')).toBe(3);
    });

    it('wire: an UPDATE joined to a derived table that reads a denied table is refused without asking', async () => {
      const rule = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'read', tablePattern: 'secrets', action: 'deny' });
      await expect(
        c.query('UPDATE orders o JOIN (SELECT id, value FROM secrets) s ON s.id = o.id SET o.status = s.value WHERE o.id = 1'),
      ).rejects.toMatchObject({ errno: 1227, message: expect.stringMatching(/read on secrets is not permitted/) });
      expect(await proxy.admin<any[]>('GET', '/approvals?status=pending')).toEqual([]);
      expect((await direct('SELECT status FROM {db}.orders WHERE id = 1'))[0].status).toBe('paid');
      await proxy.admin('DELETE', `/rules/${rule.id}`);
    });

    it('wire: the derived table is only read, so a "these tables" window for orders covers the update', async () => {
      const sql = 'UPDATE orders o JOIN (SELECT customer_id, COUNT(*) AS n FROM orders GROUP BY customer_id) t ON t.customer_id = o.customer_id SET o.status = ? WHERE o.id = ?';
      const first = c.execute(sql, ['bulk', 9]);
      const a = await decide('approve', { scope: 'tables', durationMinutes: 5 });
      expect(asked(a)).toEqual(['update:orders']);
      await first;
      const [res] = await c.execute(sql, ['bulk', 10]); // covered: no second approval
      expect((res as any).affectedRows).toBe(1);
      for (const g of await proxy.admin<any[]>('GET', '/grants')) await proxy.admin('DELETE', `/grants/${g.id}`);
    });

    it('wire: PREPARE, SET and EXECUTE in one query ask for what EXECUTE runs', async () => {
      const run = c.query("PREPARE wipe FROM 'DELETE FROM orders WHERE id = ?'; SET @id = 11; EXECUTE wipe USING @id; DEALLOCATE PREPARE wipe");
      const a = await decide('approve');
      expect(asked(a)).toEqual(['delete:orders']);
      await run;
      expect(await count('id = 11')).toBe(0);
    });

    it('wire: a DELETE hidden in an executable comment is seen and can be denied', async () => {
      const run = c.query('SELECT 1 AS one /*!50000 ; DELETE FROM orders WHERE id = 12 */');
      const a = await decide('deny');
      expect(asked(a)).toEqual(['delete:orders']);
      await expect(run).rejects.toMatchObject({ errno: 1227 });
      expect(await count('id = 12')).toBe(1);
    });

    it('wire: a transaction with a savepoint — both writes ask, ROLLBACK TO undoes only the second', async () => {
      await c.query('START TRANSACTION');
      const upd = c.query("UPDATE orders SET status = 'kept' WHERE id = 13");
      await decide('approve');
      await upd;
      await c.query('SAVEPOINT before_delete');
      const del = c.query('DELETE FROM orders WHERE id = 14');
      expect((await decide('approve')).session.transactionStatus).toBe('transaction');
      await del;
      await c.query('ROLLBACK TO SAVEPOINT before_delete');
      await c.query('COMMIT');
      expect((await direct('SELECT status FROM {db}.orders WHERE id = 13'))[0].status).toBe('kept');
      expect(await count('id = 14')).toBe(1);
    });

    it('wire: a batch with an admin statement at the end is refused whole; nothing before it runs', async () => {
      await expect(c.query("INSERT INTO audit_log (action) VALUES ('before-admin'); SET GLOBAL max_connections = 500")).rejects.toMatchObject({
        errno: 1227,
        message: expect.stringMatching(/admin is not permitted/),
      });
      expect(await count("action = 'before-admin'", 'audit_log')).toBe(0);
      expect(textOf(await query('SELECT 1; FLUSH PRIVILEGES'))).toMatch(/admin is not permitted/);
    });
  });
});
