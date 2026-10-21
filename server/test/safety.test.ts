import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import mysql from 'mysql2/promise';
import { createTestDatabase, postgresAvailable, startProxy, textOf, type TestDatabase, type TestProxy } from './helpers.js';
import { createMysqlTestDatabase, mysqlAvailable, seedMysql, type Flavour, type MysqlTestDatabase } from './mysql-helpers.js';

const pgAvailable = await postgresAvailable();
const flavours: Flavour[] = ['mysql', 'mariadb'];
const available = Object.fromEntries(await Promise.all(flavours.map(async (f) => [f, await mysqlAvailable(f)])));

describe.skipIf(!pgAvailable)('PostgreSQL safety regressions', () => {
  let db: TestDatabase, proxy: TestProxy, seeded: Awaited<ReturnType<TestProxy['seed']>>;
  let agent: Awaited<ReturnType<TestProxy['mcp']>>;
  const query = (sql: string) => agent.callTool({ name: 'query', arguments: { sql } });
  const connect = (extra = {}) => proxy.wire(seeded.client.user.username, seeded.client.token, 'shop', extra);
  const value = async () => (await db.sql('SELECT total_cents FROM orders WHERE id=1'))[0].total_cents;
  beforeAll(async () => {
    db = await createTestDatabase();
    await db.sql(`
      CREATE FUNCTION hidden_bump() RETURNS int LANGUAGE plpgsql VOLATILE AS $$ BEGIN PERFORM bump_order(1); RETURN 1; END $$;
      CREATE VIEW hidden_write AS SELECT hidden_bump() AS value;
      GRANT SELECT ON hidden_write TO ${db.role};
      CREATE FUNCTION stable_wrapper() RETURNS int LANGUAGE plpgsql STABLE AS $$ BEGIN PERFORM bump_order(1); RETURN 1; END $$;
      CREATE FUNCTION public.gen_random_uuid() RETURNS int LANGUAGE plpgsql VOLATILE AS $$ BEGIN PERFORM bump_order(1); RETURN 1; END $$;
    `);
    proxy = await startProxy();
    seeded = await proxy.seed(db);
    agent = await proxy.mcp(seeded.client.token, 'shop');
  });
  afterAll(async () => { await agent?.close(); await proxy?.close(); await db?.drop(); });

  it.each(['SELECT * FROM hidden_write', 'SELECT stable_wrapper()', 'SELECT public.gen_random_uuid()', 'EXPLAIN SELECT stable_wrapper()'])('refuses indirect writes: %s', async (sql) => {
    const before = await value();
    const wire = await connect();
    try {
      await expect(wire.query(sql)).rejects.toMatchObject({ code: '0A000' });
      const result = await query(sql);
      expect(result.isError).toBe(true);
      expect(textOf(result)).toMatch(/indirect effects/);
      expect(await value()).toBe(before);
      expect(await proxy.admin('GET', '/approvals?status=pending')).toEqual([]);
    } finally { await wire.end(); }
  });

  it('refuses mixed MCP batches before any changes, even with broad allow rules', async () => {
    const before = await value();
    const deny = await proxy.admin('POST', '/rules', { databaseId: seeded.db.id, operation: 'write', tablePattern: 'orders', action: 'deny' });
    const allow = await proxy.admin('POST', '/rules', { databaseId: seeded.db.id, operation: 'admin', action: 'allow' });
    try {
      const result = await query("UPDATE customers SET name='should not persist' WHERE id=1; SELECT * FROM hidden_write");
      expect(result.isError).toBe(true);
      expect(await value()).toBe(before);
      expect((await db.sql('SELECT name FROM customers WHERE id=1'))[0].name).toBe('Customer 1');
    } finally { await proxy.admin('DELETE', `/rules/${deny.id}`); await proxy.admin('DELETE', `/rules/${allow.id}`); }
  });

  it('checks prepared queries before forwarding them', async () => {
    const wire = await connect();
    const before = await value();
    try {
      await expect(wire.query({ text: 'SELECT * FROM hidden_write WHERE $1=1', values: [1] })).rejects.toMatchObject({ code: '0A000' });
      await expect(wire.query('PREPARE hidden AS SELECT stable_wrapper()')).rejects.toMatchObject({ code: '0A000' });
      expect(await value()).toBe(before);
    } finally { await wire.end(); }
  });

  it('refreshes metadata when an existing prepared statement is reused', async () => {
    const wire = await connect();
    try {
      await wire.query({ name: 'changing_relation', text: 'SELECT * FROM orders WHERE id=$1', values: [1] });
      // A same-named view in another schema is conservatively refused across search paths.
      await db.sql('CREATE SCHEMA shadow; CREATE VIEW shadow.orders AS SELECT hidden_bump() AS id');
      await expect(wire.query({ name: 'changing_relation', text: 'SELECT * FROM orders WHERE id=$1', values: [1] })).rejects.toMatchObject({ code: '0A000' });
    } finally { await db.sql('DROP SCHEMA IF EXISTS shadow CASCADE'); await wire.end(); }
  });

  it('enforces configured timeouts on wire sessions and prevents disabling them', async () => {
    const short = await proxy.admin('POST', '/users', { name: 'timeout-client', access: [{ databaseId: seeded.db.id, allowWire: true }] });
    await proxy.admin('PATCH', `/databases/${seeded.db.id}`, { statementTimeoutMs: 100 });
    const wire = await proxy.wire(short.user.username, short.token, 'shop', { options: '-c statement_timeout=0' });
    try {
      expect((await wire.query('SHOW statement_timeout')).rows[0].statement_timeout).toBe('100ms');
      await expect(wire.query('SELECT pg_catalog.pg_sleep(2)')).rejects.toMatchObject({ code: '57014' });
      await expect(wire.query('SET statement_timeout=0')).rejects.toMatchObject({ code: '0A000' });
      await expect(wire.query("SET statement_timeout='1s'")).rejects.toMatchObject({ code: '0A000' });
      await wire.query('RESET ALL');
      expect((await wire.query('SHOW statement_timeout')).rows[0].statement_timeout).toBe('100ms');
      await wire.query('SET statement_timeout=50');
      expect((await wire.query('SHOW statement_timeout')).rows[0].statement_timeout).toBe('50ms');
      const allow = await proxy.admin('POST', '/rules', { databaseId: seeded.db.id, operation: 'admin', action: 'allow' });
      try {
        await expect(wire.query("SELECT pg_catalog.set_config('statement_timeout','0',false)")).rejects.toMatchObject({ code: '0A000' });
      } finally { await proxy.admin('DELETE', `/rules/${allow.id}`); }
    } finally {
      await wire.end();
      await proxy.admin('PATCH', `/databases/${seeded.db.id}`, { statementTimeoutMs: 30000 });
    }
  });

  it.each(['disable', 'remove access', 'rotate token', 'delete', 'disable database'])('revokes connected clients immediately: %s', async (action) => {
    const client = await proxy.admin('POST', '/users', { name: `revoke-${action}`, access: [{ databaseId: seeded.db.id, allowWire: true }] });
    const wire = await proxy.wire(client.user.username, client.token, 'shop');
    const closed = new Promise<void>((resolve) => wire.once('end', resolve));
    if (action === 'disable') await proxy.admin('PATCH', `/users/${client.user.id}`, { enabled: false });
    if (action === 'remove access') await proxy.admin('PATCH', `/users/${client.user.id}`, { access: [] });
    if (action === 'rotate token') await proxy.admin('POST', `/users/${client.user.id}/rotate-token`);
    if (action === 'delete') await proxy.admin('DELETE', `/users/${client.user.id}`);
    if (action === 'disable database') await proxy.admin('PATCH', `/databases/${seeded.db.id}`, { enabled: false });
    await closed;
    await expect(wire.query('SELECT 42')).rejects.toThrow();
    await wire.end();
    if (action === 'disable database') await proxy.admin('PATCH', `/databases/${seeded.db.id}`, { enabled: true });
  });

  it('does not execute an MCP write approved after its client was disabled', async () => {
    const client = await proxy.admin('POST', '/users', { name: 'pending-mcp', access: [{ databaseId: seeded.db.id, allowMcp: true }] });
    const mcp = await proxy.mcp(client.token, 'shop');
    try {
      const before = await value();
      const call = mcp.callTool({ name: 'query', arguments: { sql: 'UPDATE orders SET total_cents=999 WHERE id=1' } });
      const pending = await proxy.nextPending();
      await proxy.admin('PATCH', `/users/${client.user.id}`, { enabled: false });
      await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'approve' });
      expect((await call).isError).toBe(true);
      expect(await value()).toBe(before);
    } finally { await mcp.close(); }
  });

  it('fails closed when relation metadata cannot be inspected', async () => {
    await db.sql('REVOKE SELECT ON pg_catalog.pg_class FROM PUBLIC');
    try {
      const result = await query('SELECT * FROM orders');
      expect(result.isError).toBe(true);
      expect(textOf(result)).toMatch(/Cannot verify database relation metadata/);
    } finally { await db.sql('GRANT SELECT ON pg_catalog.pg_class TO PUBLIC'); }
  });
});

for (const flavour of flavours) describe.skipIf(!available[flavour])(`${flavour} safety regressions`, () => {
  let db: MysqlTestDatabase, proxy: TestProxy, seeded: Awaited<ReturnType<typeof seedMysql>>;
  let agent: Awaited<ReturnType<TestProxy['mcp']>>;
  const query = (sql: string) => agent.callTool({ name: 'query', arguments: { sql } });
  const connect = (user = seeded.client.user.username, password = seeded.client.token) => mysql.createConnection({ host: '127.0.0.1', port: proxy.mysqlWirePort, user, password, database: 'shop' });
  const value = async () => (await db.sql('SELECT total_cents FROM orders WHERE id=1'))[0].total_cents;
  beforeAll(async () => {
    db = await createMysqlTestDatabase(flavour);
    await db.sql('CREATE VIEW hidden_write AS SELECT bump_order(1) AS value');
    await db.sql('CREATE TABLE nontransactional(id int PRIMARY KEY, value int) ENGINE=MyISAM');
    await db.sql('INSERT INTO nontransactional VALUES (1, 0)');
    proxy = await startProxy(); seeded = await seedMysql(proxy, db);
    agent = await proxy.mcp(seeded.client.token, 'shop');
  });
  afterAll(async () => { await agent?.close(); await proxy?.close(); await db?.drop(); });

  it.each(['SELECT * FROM hidden_write', 'SELECT bump_order(1)', 'EXPLAIN SELECT bump_order(1)'])('refuses hidden writes: %s', async (sql) => {
    const wire = await connect(), before = await value();
    try {
      await expect(wire.query(sql)).rejects.toThrow(/indirect effects/);
      expect((await query(sql)).isError).toBe(true);
      expect(await value()).toBe(before);
    } finally { await wire.end(); }
  });

  it('refuses indirect effects in prepared statements', async () => {
    const wire = await connect(), before = await value();
    try { await expect(wire.execute('SELECT * FROM hidden_write WHERE ?=1', [1])).rejects.toThrow(/indirect effects/); expect(await value()).toBe(before); }
    finally { await wire.end(); }
  });

  it.each(['CREATE TABLE atomicity_probe(id int)', 'TRUNCATE orders'])('rejects implicit-commit batches before writing: %s', async (ddl) => {
    const before = await value();
    const result = await query(`UPDATE orders SET total_cents=total_cents+1000 WHERE id=1; ${ddl}; SELECT * FROM missing_review_table`);
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/not atomic/);
    expect(await value()).toBe(before);
    expect(await proxy.admin('GET', '/approvals?status=pending')).toEqual([]);
    expect(await db.sql("SHOW TABLES LIKE 'atomicity_probe'")).toEqual([]);
  });

  it('refuses writes to tables whose storage engine cannot roll back', async () => {
    const result = await query('UPDATE nontransactional SET value=1 WHERE id=1; SELECT * FROM missing_review_table');
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/nontransactional/);
    expect((await db.sql('SELECT value FROM nontransactional WHERE id=1'))[0].value).toBe(0);
  });

  it('preserves rollback for ordinary approved DML batches', async () => {
    const before = await value();
    const call = query('UPDATE orders SET total_cents=total_cents+1000 WHERE id=1; SELECT * FROM missing_review_table');
    const pending = await proxy.nextPending();
    await proxy.admin('POST', `/approvals/${pending.id}/decision`, { decision: 'approve' });
    expect((await call).isError).toBe(true);
    expect(await value()).toBe(before);
  });

  it.each(['disable', 'remove access', 'rotate token', 'disable database'])('closes existing wire sessions: %s', async (action) => {
    const client = await proxy.admin('POST', '/users', { name: `revoke-${action}`, access: [{ databaseId: seeded.db.id, allowWire: true }] });
    const wire = await connect(client.user.username, client.token);
    wire.on('error', () => {});
    const closed = new Promise<void>((resolve) => wire.once('end', resolve));
    if (action === 'disable') await proxy.admin('PATCH', `/users/${client.user.id}`, { enabled: false });
    if (action === 'remove access') await proxy.admin('PATCH', `/users/${client.user.id}`, { access: [] });
    if (action === 'rotate token') await proxy.admin('POST', `/users/${client.user.id}/rotate-token`);
    if (action === 'disable database') await proxy.admin('PATCH', `/databases/${seeded.db.id}`, { enabled: false });
    await closed;
    await expect(wire.query('SELECT 42')).rejects.toThrow();
    await wire.end();
    if (action === 'disable database') await proxy.admin('PATCH', `/databases/${seeded.db.id}`, { enabled: true });
  });
});
