import { spawn } from 'node:child_process';
import mysql from 'mysql2/promise';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startProxy, type TestProxy } from './helpers.js';
import { createMysqlTestDatabase, mysqlAvailable, seedMysql, type Flavour, type MysqlTestDatabase } from './mysql-helpers.js';

const flavours: Flavour[] = ['mysql', 'mariadb'];
const available = Object.fromEntries(await Promise.all(flavours.map(async (f) => [f, await mysqlAvailable(f)] as const)));

/** The real command-line client from the server's own image (docker), if docker is usable here. */
const cliImage: Record<Flavour, { image: string; bin: string }> = { mysql: { image: 'mysql:8.4', bin: 'mysql' }, mariadb: { image: 'mariadb:11', bin: 'mariadb' } };
const dockerOk = await new Promise<boolean>((resolve) => {
  const p = spawn('docker', ['image', 'inspect', 'mysql:8.4', 'mariadb:11'], { stdio: 'ignore' });
  p.on('error', () => resolve(false));
  p.on('close', (code) => resolve(code === 0));
});

function cli(flavour: Flavour, port: number, user: string, password: string, args: string[], stdin = ''): Promise<{ code: number; out: string }> {
  const { image, bin } = cliImage[flavour];
  const p = spawn('docker', ['run', '--rm', '-i', '--network', 'host', '-e', `MYSQL_PWD=${password}`, image, bin, '-h', '127.0.0.1', '-P', String(port), '-u', user, ...args]);
  let out = '';
  p.stdout.on('data', (d) => (out += d));
  p.stderr.on('data', (d) => (out += d));
  p.stdin.end(stdin);
  return new Promise((resolve) => p.on('close', (code) => resolve({ code: code ?? -1, out: out.trim() })));
}

describe.each(flavours)('MySQL wire listener against real %s', (flavour) => {
  describe.skipIf(!available[flavour])(flavour, () => {
    let tdb: MysqlTestDatabase;
    let proxy: TestProxy;
    let db: any;
    let user: any;
    let token: string;
    const connect = (extra: Partial<mysql.ConnectionOptions> = {}) =>
      mysql.createConnection({ host: '127.0.0.1', port: proxy.mysqlWirePort, user: user.username, password: token, database: 'shop', ...extra });
    const decide = async (decision: 'approve' | 'deny', extra: Record<string, unknown> = {}) => {
      const pending = await proxy.nextPending();
      await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision, ...extra });
      return pending;
    };
    const direct = (q: string) => tdb.sql(q.replaceAll('{db}', tdb.database));

    beforeAll(async () => {
      tdb = await createMysqlTestDatabase(flavour);
      proxy = await startProxy();
      const seeded = await seedMysql(proxy, tdb);
      db = seeded.db;
      ({ user, token } = seeded.client);
    });

    afterAll(async () => {
      await proxy?.close();
      await tdb?.drop();
    });

    describe('login', () => {
      it('accepts the client token, refuses anything else', async () => {
        const c = await connect();
        const [rows] = await c.query('SELECT DATABASE() AS d, CURRENT_USER() AS u');
        expect((rows as any)[0].d).toBe(tdb.database);
        await c.end();
        await expect(connect({ password: 'wrong' })).rejects.toMatchObject({ errno: 1045 });
        await expect(connect({ user: 'nobody' })).rejects.toMatchObject({ errno: 1045 });
      });

      it('requires a database this client may use over the wire', async () => {
        await expect(connect({ database: undefined })).rejects.toMatchObject({ errno: 1046 });
        await expect(connect({ database: 'nope' })).rejects.toMatchObject({ errno: 1049 });
        const other = await proxy.admin('POST', '/databases', { ...db, id: undefined, slug: 'shop2', engine: flavour, password: tdb.password });
        await expect(connect({ database: 'shop2' })).rejects.toMatchObject({ errno: 1044 });
        await proxy.admin('DELETE', `/databases/${other.id}`);
      });

      it('verifies mysql_native_password replies against the stored double hash', async () => {
        const { verifyScramble, scramble, NATIVE, SHA2 } = await import('../src/engines/mysql/wire/auth.js');
        const { mysqlVerifier } = await import('../src/auth.js');
        const challenge = Buffer.from('abcdefghijklmnopqrst');
        const v = mysqlVerifier(token);
        expect(verifyScramble(NATIVE, v.mysqlNativeHash, challenge, scramble(NATIVE, token, challenge))).toBe(true);
        expect(verifyScramble(NATIVE, v.mysqlNativeHash, challenge, scramble(NATIVE, 'x', challenge))).toBe(false);
        expect(verifyScramble(SHA2, v.mysqlSha2Hash, challenge, scramble(SHA2, token, challenge))).toBe(true);
      });
    });

    describe('statements', () => {
      let c: mysql.Connection;
      beforeAll(async () => {
        c = await connect({ multipleStatements: true });
      });
      afterAll(async () => {
        await c?.end();
      });

      it('reads run immediately, text and binary protocol', async () => {
        const [a] = await c.query('SELECT COUNT(*) AS n FROM orders');
        expect(a).toEqual([{ n: 50 }]);
        const [b] = await c.execute('SELECT name FROM customers WHERE id = ?', [3]);
        expect(b).toEqual([{ name: 'Customer 3' }]);
      });

      it('holds a write until approved; the card shows wire, the verb and bound parameters', async () => {
        const run = c.execute('UPDATE orders SET status = ? WHERE id = ?', ['refunded', 1]);
        const pending = await decide('approve');
        expect(pending).toMatchObject({ surface: 'wire', verbs: ['update'], tables: ['orders'], params: ['refunded', '1'] });
        expect(pending.estimate.rows).toBe(1);
        const [res] = await run;
        expect((res as any).affectedRows).toBe(1);
        expect(await direct('SELECT status FROM {db}.orders WHERE id = 1')).toEqual([{ status: 'refunded' }]);
      });

      it('a denial is an ERR the client sees; nothing runs', async () => {
        const run = c.query('DELETE FROM orders');
        await decide('deny');
        await expect(run).rejects.toMatchObject({ errno: 1227, sqlState: '42000', message: expect.stringMatching(/denied by the operator/) });
        expect(await direct('SELECT COUNT(*) AS n FROM {db}.orders')).toEqual([{ n: 50 }]);
      });

      it('a denial inside a transaction leaves the transaction usable (MySQL semantics)', async () => {
        const rule = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'insert', action: 'allow' });
        await c.query('START TRANSACTION');
        await c.query("INSERT INTO customers (email, name) VALUES ('tx@example.com', 'Tx')");
        const del = c.query('DELETE FROM customers WHERE id = 2');
        const pending = await decide('deny');
        expect(pending.session.transactionStatus).toBe('transaction');
        await expect(del).rejects.toMatchObject({ errno: 1227 });
        await c.query('COMMIT');
        expect(await direct("SELECT COUNT(*) AS n FROM {db}.customers WHERE email = 'tx@example.com' OR id = 2")).toEqual([{ n: 2 }]);
        await proxy.admin('DELETE', `/rules/${rule.id}`);
      });

      it('multi-statement queries are decided as a whole', async () => {
        const [sets] = await c.query('SELECT 1 AS a; SELECT name FROM customers WHERE id = 4');
        expect(sets).toEqual([[{ a: 1 }], [{ name: 'Customer 4' }]]);
        const run = c.query("UPDATE orders SET status = 'a' WHERE id = 3; DELETE FROM orders WHERE id = 3");
        const pending = await decide('deny');
        expect(pending.verbs).toEqual(['update', 'delete']);
        await expect(run).rejects.toMatchObject({ errno: 1227 });
        expect(await direct('SELECT status FROM {db}.orders WHERE id = 3')).toEqual([{ status: 'paid' }]);
      });

      it('SQL-level PREPARE / EXECUTE is gated at EXECUTE with what was prepared', async () => {
        await c.query("PREPARE del FROM 'DELETE FROM orders WHERE id = ?'");
        await c.query('SET @id = 5');
        const run = c.query('EXECUTE del USING @id');
        const pending = await decide('deny');
        expect(pending.verbs).toEqual(['delete']);
        await expect(run).rejects.toMatchObject({ errno: 1227 });
        await c.query('DEALLOCATE PREPARE del');
      });

      it('stored functions ask, admin statements are refused, USE is limited to this database', async () => {
        const run = c.query('SELECT bump_order(6) AS x');
        expect((await decide('deny')).verbs).toEqual(['function']);
        await expect(run).rejects.toMatchObject({ errno: 1227 });
        await expect(c.query("SET SESSION sql_mode = 'ANSI_QUOTES'")).rejects.toMatchObject({ errno: 1227, message: /admin is not permitted/ });
        await expect(c.query("SELECT * FROM orders INTO OUTFILE '/tmp/x'")).rejects.toMatchObject({ errno: 1227 });
        await expect(c.query('USE mysql')).rejects.toMatchObject({ errno: 1227 });
        await c.query('USE shop');
        const [[row]] = (await c.query('SELECT DATABASE() AS d')) as any;
        expect(row.d).toBe(tdb.database);
      });

      it('an approved sql_mode change is followed: the proxy keeps lexing like the server', async () => {
        const rule = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'admin', action: 'allow' });
        const s = await connect();
        await s.query("SET SESSION sql_mode = CONCAT(@@sql_mode, ',ANSI_QUOTES')");
        await proxy.admin('DELETE', `/rules/${rule.id}`);
        // With ANSI_QUOTES, "secrets" is a table, not a string: a deny on secrets must apply.
        const deny = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'read', tablePattern: 'secrets', action: 'deny' });
        await expect(s.query('SELECT * FROM "secrets"')).rejects.toMatchObject({ errno: 1227, message: /read on secrets/ });
        await proxy.admin('DELETE', `/rules/${deny.id}`);
        await s.end();
      });

      it('audits wire statements with row counts', async () => {
        const audit = await proxy.admin<any[]>('GET', '/audit?limit=100');
        expect(audit.find((a) => a.sql === 'UPDATE orders SET status = ? WHERE id = ?')).toMatchObject({ surface: 'wire', decision: 'approved', rowCount: 1 });
        expect(audit.find((a) => a.sql === 'SELECT COUNT(*) AS n FROM orders')).toMatchObject({ decision: 'allowed', rowCount: 1 });
      });
    });

    describe('cancel', () => {
      it('KILL QUERY from another connection withdraws a held statement', async () => {
        const a = await connect();
        const b = await connect();
        const run = a.query("UPDATE orders SET status = 'k' WHERE id = 7");
        const pending = await proxy.nextPending();
        await b.query(`KILL QUERY ${a.threadId}`);
        await expect(run).rejects.toMatchObject({ errno: 1317 });
        const [after] = await proxy.admin<any[]>('GET', `/approvals?limit=1`);
        expect(after).toMatchObject({ id: pending.id, status: 'cancelled' });
        const [rows] = await a.query('SELECT 1 AS ok');
        expect(rows).toEqual([{ ok: 1 }]);
        await a.end();
        await b.end();
      });

      it('KILL QUERY interrupts a statement running upstream', async () => {
        const a = await connect();
        const b = await connect();
        const started = Date.now();
        const run = a.query('SELECT SLEEP(20) AS s');
        await new Promise((r) => setTimeout(r, 300));
        await b.query(`KILL QUERY ${a.threadId}`);
        const result = await run.then(([rows]) => rows, (e) => e);
        expect(Date.now() - started).toBeLessThan(5000);
        // MySQL returns 1 from an interrupted SLEEP(); MariaDB reports an error.
        expect(result instanceof Error ? (result as any).errno : (result as any)[0].s).toBeDefined();
        await a.end();
        await b.end();
      });

      it("can't kill another client's connection", async () => {
        const a = await connect();
        const other = await proxy.admin('POST', '/users', { name: 'other', access: [{ databaseId: db.id, allowMcp: false, allowWire: true }] });
        const b = await connect({ user: other.user.username, password: other.token });
        await expect(b.query(`KILL QUERY ${a.threadId}`)).rejects.toMatchObject({ errno: 1095 });
        await expect(b.query('KILL QUERY 1')).rejects.toMatchObject({ errno: 1094 });
        await a.end();
        await b.end();
      });
    });

    it('read-only clients get a READ ONLY session', async () => {
      const ro = await proxy.admin('POST', '/users', { name: 'reader', access: [{ databaseId: db.id, allowMcp: false, allowWire: true }] });
      for (const op of ['write', 'ddl', 'admin']) await proxy.admin('POST', '/rules', { databaseId: db.id, userId: ro.user.id, operation: op, action: 'deny' });
      const c = await connect({ user: ro.user.username, password: ro.token });
      const [[row]] = (await c.query('SELECT @@transaction_read_only AS ro')) as any;
      expect(Number(row.ro)).toBe(1);
      await expect(c.query('DELETE FROM orders')).rejects.toMatchObject({ errno: 1227 });
      await c.end();
    });

    describe.skipIf(!dockerOk)(`the real ${flavour} command-line client`, () => {
      it('runs reads and shows a table', async () => {
        const r = await cli(flavour, proxy.mysqlWirePort, user.username, token, ['--table', 'shop', '-e', 'SELECT id, name FROM customers ORDER BY id LIMIT 2']);
        expect(r.out).toMatch(/\|\s+1 \| Customer 1\s+\|/);
        expect(r.code).toBe(0);
      });

      it('waits for approval on writes, and reports a denial', async () => {
        const run = cli(flavour, proxy.mysqlWirePort, user.username, token, ['shop'], "UPDATE orders SET status = 'cli' WHERE id = 8;\nDELETE FROM orders WHERE id = 8;\nSELECT status FROM orders WHERE id = 8;\n");
        const first = await decide('approve');
        expect(first.session.applicationName).toMatch(/^(mysql|mariadb)$/);
        await decide('deny');
        const r = await run;
        expect(r.out).toMatch(/ERROR 1227 \(42000\).*denied by the operator/);
        expect(await direct('SELECT status FROM {db}.orders WHERE id = 8')).toEqual([{ status: 'cli' }]);
      });

      it('switches database with \\u and rejects other databases', async () => {
        const r = await cli(flavour, proxy.mysqlWirePort, user.username, token, ['shop', '--force'], 'use shop\nSELECT 1 AS ok;\nuse mysql\n');
        expect(r.out).toMatch(/ok\s+1/);
        expect(r.out).toMatch(/ERROR 1044/);
      });

      it('logs in with mysql_native_password when the client prefers it', async () => {
        const r = await cli(flavour, proxy.mysqlWirePort, user.username, token, ['--default-auth=mysql_native_password', 'shop', '-e', 'SELECT 2 AS two']);
        expect(r.out).toMatch(/two\s+2/);
      });

      it('a wrong token is refused', async () => {
        const r = await cli(flavour, proxy.mysqlWirePort, user.username, 'nope', ['shop', '-e', 'SELECT 1']);
        expect(r.out).toMatch(/ERROR 1045/);
      });
    });
  });
});
