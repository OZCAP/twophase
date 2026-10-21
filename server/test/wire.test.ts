import net from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { cancelRequest, FrameReader, message, parseFields, Reader, saslInitialResponse, saslResponse, startupMessage, type Frame } from '../src/engines/postgres/wire/protocol.js';
import { ScramClientSession } from '../src/engines/postgres/wire/scram.js';
import { createTestDatabase, postgresAvailable, startProxy, type TestDatabase, type TestProxy } from './helpers.js';

const available = await postgresAvailable();

/** Bare-bones protocol client, for things node-postgres can't express (pipelining a mixed batch). */
async function rawConnect(port: number, user: string, password: string, database: string) {
  const socket = net.connect({ host: '127.0.0.1', port });
  const reader = new FrameReader();
  const frames: Frame[] = [];
  let wake: (() => void) | null = null;
  socket.on('data', (d) => {
    reader.push(d);
    for (let f = reader.next(); f; f = reader.next()) frames.push(f);
    wake?.();
  });
  const next = async (): Promise<Frame> => {
    while (!frames.length) await new Promise<void>((r) => (wake = r));
    return frames.shift()!;
  };
  await new Promise((r) => socket.once('connect', r));
  socket.write(startupMessage({ user, database }));
  const scram = new ScramClientSession(password);
  for (;;) {
    const f = await next();
    if (f.type === 'R') {
      const kind = f.body.readInt32BE(0);
      if (kind === 10) socket.write(saslInitialResponse('SCRAM-SHA-256', scram.first()));
      if (kind === 11) socket.write(saslResponse(scram.final(f.body.subarray(4).toString())));
    }
    if (f.type === 'E') throw new Error(parseFields(f.body).get('M'));
    if (f.type === 'Z') break;
  }
  const cstr = (s: string) => Buffer.concat([Buffer.from(s), Buffer.from([0])]);
  const i16 = (n: number) => Buffer.from([n >> 8, n & 255]);
  return {
    socket,
    parse: (sql: string, name = '') => message('P', cstr(name), cstr(sql), i16(0)),
    bind: (statement = '') => message('B', cstr(''), cstr(statement), i16(0), i16(0), i16(0)),
    execute: () => message('E', cstr(''), Buffer.from([0, 0, 0, 0])),
    sync: () => message('S'),
    /** Collect messages until ReadyForQuery; returns [types, errors, txStatus]. */
    async untilReady() {
      const types: string[] = [];
      const errors: string[] = [];
      for (;;) {
        const f = await next();
        types.push(f.type);
        if (f.type === 'E') errors.push(`${parseFields(f.body).get('C')}: ${parseFields(f.body).get('M')}`);
        if (f.type === 'Z') return { types, errors, status: String.fromCharCode(f.body[0]) };
      }
    },
  };
}

describe.skipIf(!available)('Postgres wire listener against real Postgres', () => {
  let tdb: TestDatabase;
  let proxy: TestProxy;
  let db: any;
  let client: { user: any; token: string };
  const connect = (extra = {}) => proxy.wire(client.user.username, client.token, 'shop', extra);
  const decideNext = async (decision: 'approve' | 'deny', extra = {}) => {
    const a = await proxy.nextPending();
    await proxy.admin('POST', `/approvals/${a.id}/decision`, { decision, ...extra });
    return a;
  };

  beforeAll(async () => {
    tdb = await createTestDatabase();
    proxy = await startProxy();
    ({ db, client } = await proxy.seed(tdb));
  });
  afterAll(async () => {
    await proxy?.close();
    await tdb?.drop();
  });

  describe('authentication', () => {
    it('logs in with SCRAM using the client token', async () => {
      const c = await connect();
      const r = await c.query('SELECT current_database() AS db, current_user AS u');
      expect(r.rows[0]).toEqual({ db: tdb.database, u: tdb.role });
      await c.end();
    });

    it('rejects a wrong token, an unknown user, an unknown database, and clients without wire access', async () => {
      await expect(proxy.wire(client.user.username, 'tp_wrong', 'shop')).rejects.toThrow(/password authentication failed/);
      await expect(proxy.wire('nobody', client.token, 'shop')).rejects.toThrow(/password authentication failed/);
      await expect(proxy.wire(client.user.username, client.token, 'nope')).rejects.toThrow(/database "nope" does not exist/);
      const mcpOnly = await proxy.admin('POST', '/users', { name: 'mcp only', access: [{ databaseId: db.id, allowMcp: true, allowWire: false }] });
      await expect(proxy.wire(mcpOnly.user.username, mcpOnly.token, 'shop')).rejects.toThrow(/no Postgres access/);
    });

    it('rejects startup settings that could change privileges or desync the parser', async () => {
      await expect(connect({ options: '-c default_transaction_read_only=off' })).rejects.toThrow(/can't be set at connection time/);
      await expect(connect({ options: '-c standard_conforming_strings=off' })).rejects.toThrow(/can't be set at connection time/);
    });
  });

  describe('statements', () => {
    it('runs reads directly with the simple and extended protocols', async () => {
      const c = await connect();
      expect((await c.query('SELECT count(*)::int AS n FROM orders')).rows).toEqual([{ n: 50 }]);
      expect((await c.query('SELECT name FROM customers WHERE id = $1', [3])).rows).toEqual([{ name: 'Customer 3' }]);
      expect((await c.query({ name: 'by_id', text: 'SELECT id FROM orders WHERE id = $1', values: [9] })).rows).toEqual([{ id: 9 }]);
      expect((await c.query({ name: 'by_id', text: 'SELECT id FROM orders WHERE id = $1', values: [10] })).rows).toEqual([{ id: 10 }]);
      await c.end();
    });

    it('holds a write, sends a "waiting for approval" notice, and runs it once approved', async () => {
      const c = await connect();
      const notices: string[] = [];
      c.on('notice', (n) => notices.push(n.message ?? ''));
      const update = c.query("UPDATE orders SET status = 'refunded' WHERE id = 1");
      const a = await decideNext('approve');
      expect(a).toMatchObject({ surface: 'wire', operations: ['write'], tables: ['orders'] });
      expect((await update).rowCount).toBe(1);
      expect(notices.some((n) => /waiting for approval/.test(n))).toBe(true);
      expect(await tdb.sql('SELECT status FROM orders WHERE id = 1')).toEqual([{ status: 'refunded' }]);
      await c.end();
    });

    it('shows Bind parameters on the approval for extended-protocol writes', async () => {
      const c = await connect();
      const update = c.query('UPDATE orders SET status = $1 WHERE id = $2', ['pending', 2]);
      const a = await decideNext('approve');
      expect(a.params).toEqual(['pending', '2']);
      expect((await update).rowCount).toBe(1);
      await c.end();
    });

    it('denies with SQLSTATE 42501 and leaves an explicit transaction aborted, like a real error', async () => {
      const c = await connect();
      await c.query('BEGIN');
      await c.query("UPDATE orders SET status = 'in-txn' WHERE id = 3"
        .replace('UPDATE', 'SELECT 1; UPDATE')
        .replace(/.*/, 'SELECT 1')); // a read inside the transaction first
      const del = c.query('DELETE FROM orders WHERE id = 3');
      await decideNext('deny');
      await expect(del).rejects.toMatchObject({ code: '42501', message: /denied by the operator/ });
      await expect(c.query('SELECT 1')).rejects.toMatchObject({ code: '25P02' });
      expect((await c.query('COMMIT')).command).toBe('ROLLBACK');
      expect(await tdb.sql('SELECT count(*)::int AS n FROM orders WHERE id = 3')).toEqual([{ n: 1 }]);
      await c.end();
    });

    it('denies by policy without asking (admin statements, parse errors)', async () => {
      const c = await connect();
      await expect(c.query('SELECT pg_terminate_backend(1)')).rejects.toMatchObject({ code: '42501', message: /admin is not permitted/ });
      await expect(c.query('SET ROLE postgres')).rejects.toMatchObject({ code: '42501' });
      await expect(c.query('SELEC 1')).rejects.toMatchObject({ code: '42501', message: /could not be parsed/ });
      expect((await c.query('SELECT 1 AS ok')).rows).toEqual([{ ok: 1 }]);
      await c.end();
    });

    it('catches EXPLAIN ANALYZE of a write', async () => {
      const c = await connect();
      const q = c.query("EXPLAIN ANALYZE UPDATE orders SET status = 'probe' WHERE id = 4");
      const a = await decideNext('deny');
      expect(a.operations).toEqual(['write']);
      await expect(q).rejects.toMatchObject({ code: '42501' });
      expect(await tdb.sql('SELECT status FROM orders WHERE id = 4')).toEqual([{ status: 'paid' }]);
      await c.end();
    });

    it('a denied statement mid-batch rolls back what came before it in the same implicit transaction', async () => {
      const deny = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'write', tablePattern: 'secrets', action: 'deny' });
      const allow = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'write', tablePattern: 'customers', action: 'allow' });
      const raw = await rawConnect(proxy.wirePort, client.user.username, client.token, 'shop');
      raw.socket.write(
        Buffer.concat([
          raw.parse("INSERT INTO customers (email, name) VALUES ('pipelined@example.com', 'P')"),
          raw.bind(),
          raw.execute(),
          raw.parse('DELETE FROM secrets'),
          raw.bind(),
          raw.execute(),
          raw.sync(),
        ]),
      );
      const result = await raw.untilReady();
      expect(result.errors).toEqual([expect.stringMatching(/^42501: .*delete on secrets is not permitted/)]);
      expect(result.status).toBe('I');
      expect(await tdb.sql("SELECT count(*)::int AS n FROM customers WHERE email = 'pipelined@example.com'")).toEqual([{ n: 0 }]);
      expect(await tdb.sql('SELECT count(*)::int AS n FROM secrets')).toEqual([{ n: 1 }]);

      // The connection is still healthy afterwards.
      raw.socket.write(Buffer.concat([raw.parse('SELECT 1'), raw.bind(), raw.execute(), raw.sync()]));
      expect((await raw.untilReady()).errors).toEqual([]);
      raw.socket.destroy();
      await proxy.admin('DELETE', `/rules/${deny.id}`);
      await proxy.admin('DELETE', `/rules/${allow.id}`);
    });

    it('verb-level rules apply on the wire: upsert counts as insert + update', async () => {
      const rule = await proxy.admin('POST', '/rules', { databaseId: db.id, operation: 'insert', action: 'allow' });
      const c = await connect();
      expect((await c.query("INSERT INTO customers (email, name) VALUES ('wire-verb@example.com', 'W')")).rowCount).toBe(1);
      // ON CONFLICT DO UPDATE may rewrite existing rows, so it still asks for the update part.
      const upsert = c.query("INSERT INTO customers (email, name) VALUES ('wire-verb@example.com', 'W2') ON CONFLICT (email) DO UPDATE SET name = excluded.name");
      const a = await decideNext('deny');
      expect(a.verbs).toEqual(['update']);
      await expect(upsert).rejects.toMatchObject({ code: '42501' });
      await c.end();
      await proxy.admin('DELETE', `/rules/${rule.id}`);
    });

    it('a cancel request (Ctrl+C) withdraws a held statement', async () => {
      const c = await connect();
      const q = c.query('DELETE FROM orders WHERE id = 5');
      const pending = await proxy.nextPending();
      const anyClient = c as unknown as { processID: number; secretKey: number };
      const s = net.connect({ host: '127.0.0.1', port: proxy.wirePort }, () => s.end(cancelRequest(anyClient.processID, anyClient.secretKey)));
      await expect(q).rejects.toMatchObject({ code: '57014', message: /canceling statement due to user request/ });
      expect((await proxy.admin('GET', `/approvals/${pending.id}`)).status).toBe('cancelled');
      expect((await c.query('SELECT 1 AS ok')).rows).toEqual([{ ok: 1 }]);
      await c.end();
    });

    it('a cancel request also reaches a running query upstream', async () => {
      const c = await connect();
      const q = c.query('SELECT pg_sleep(10)');
      await new Promise((r) => setTimeout(r, 300));
      const anyClient = c as unknown as { processID: number; secretKey: number };
      const s = net.connect({ host: '127.0.0.1', port: proxy.wirePort }, () => s.end(cancelRequest(anyClient.processID, anyClient.secretKey)));
      await expect(q).rejects.toMatchObject({ code: '57014' });
      await c.end();
    });

    it('re-executing a named prepared write asks again (unless a trust window covers it)', async () => {
      const c = await connect();
      const stmt = { name: 'bump', text: 'UPDATE orders SET total_cents = total_cents + 1 WHERE id = $1' };
      const first = c.query({ ...stmt, values: [6] });
      await decideNext('approve', { scope: 'tables', durationMinutes: 5 });
      await first;
      expect((await c.query({ ...stmt, values: [6] })).rowCount).toBe(1); // covered by the trust window
      for (const g of await proxy.admin<any[]>('GET', '/grants')) await proxy.admin('DELETE', `/grants/${g.id}`);
      const third = c.query({ ...stmt, values: [6] });
      await decideNext('deny');
      await expect(third).rejects.toMatchObject({ code: '42501' });
      await c.end();
    });

    it('SQL-level PREPARE/EXECUTE is classified by the prepared statement', async () => {
      const c = await connect();
      await c.query('PREPARE wipe AS DELETE FROM orders');
      const exec = c.query('EXECUTE wipe');
      const a = await decideNext('deny');
      expect(a.operations).toEqual(['write']);
      await expect(exec).rejects.toMatchObject({ code: '42501' });
      expect(await tdb.sql('SELECT count(*)::int AS n FROM orders')).toEqual([{ n: 50 }]);
      await c.end();
    });

    it('does not replace the analysis when SQL PREPARE fails on a duplicate name', async () => {
      const c = await connect();
      await c.query('PREPARE keep_original AS DELETE FROM orders');
      await expect(c.query('PREPARE keep_original AS SELECT 1')).rejects.toMatchObject({ code: '42P05' });
      const run = c.query('EXECUTE keep_original');
      expect((await decideNext('deny')).verbs).toEqual(['delete']);
      await expect(run).rejects.toMatchObject({ code: '42501' });
      expect(await tdb.sql('SELECT count(*)::int AS n FROM orders')).toEqual([{ n: 50 }]);
      await c.end();
    });

    it('does not replace the analysis when a named protocol Parse fails', async () => {
      const raw = await rawConnect(proxy.wirePort, client.user.username, client.token, 'shop');
      try {
        raw.socket.write(Buffer.concat([raw.parse('DELETE FROM orders', 'keep_original'), raw.sync()]));
        expect((await raw.untilReady()).errors).toEqual([]);
        raw.socket.write(Buffer.concat([raw.parse('SELECT 1', 'keep_original'), raw.sync()]));
        expect((await raw.untilReady()).errors).toEqual([expect.stringMatching(/^42P05:/)]);
        raw.socket.write(Buffer.concat([raw.bind('keep_original'), raw.execute(), raw.sync()]));
        expect((await decideNext('deny')).verbs).toEqual(['delete']);
        expect((await raw.untilReady()).errors).toEqual([expect.stringMatching(/^42501:/)]);
        expect(await tdb.sql('SELECT count(*)::int AS n FROM orders')).toEqual([{ n: 50 }]);
      } finally { raw.socket.destroy(); }
    });

    it('rejects legacy fast-path function calls', async () => {
      const raw = await rawConnect(proxy.wirePort, client.user.username, client.token, 'shop');
      raw.socket.write(message('F', Buffer.alloc(4), Buffer.from([0, 0, 0, 0, 0, 0, 0, 0])));
      const r = await raw.untilReady();
      expect(r.errors).toEqual([expect.stringMatching(/^0A000: .*fast-path/)]);
      raw.socket.destroy();
    });
  });

  describe('read-only clients', () => {
    it('forces default_transaction_read_only for clients whose policy can never write', async () => {
      const ro = await proxy.admin('POST', '/users', { name: 'reader', access: [{ databaseId: db.id, allowMcp: true, allowWire: true }] });
      for (const operation of ['write', 'ddl']) {
        await proxy.admin('POST', '/rules', { databaseId: db.id, userId: ro.user.id, operation, action: 'deny' });
      }
      const c = await proxy.wire(ro.user.username, ro.token, 'shop');
      expect((await c.query('SHOW transaction_read_only')).rows).toEqual([{ transaction_read_only: 'on' }]);
      await expect(c.query('BEGIN READ WRITE')).rejects.toMatchObject({ code: '42501' });
      await c.end();
    });
  });

  describe('audit', () => {
    it('records wire statements with row counts and SQLSTATEs', async () => {
      const audit = await proxy.admin<any[]>('GET', '/audit?limit=200');
      expect(audit.find((a) => a.sql === "UPDATE orders SET status = 'refunded' WHERE id = 1")).toMatchObject({ surface: 'wire', decision: 'approved', rowCount: 1 });
      expect(audit.find((a) => a.sql === 'SELECT count(*)::int AS n FROM orders')).toMatchObject({ decision: 'allowed', rowCount: 1 });
      expect(audit.some((a) => a.surface === 'wire' && a.decision === 'cancelled')).toBe(true);
      expect(audit.some((a) => a.surface === 'wire' && a.decision === 'denied' && a.sqlstate === '42501')).toBe(true);
    });
  });
});
