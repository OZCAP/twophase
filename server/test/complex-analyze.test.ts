// Statements that do several things at once: every part must be seen, with the right verb and table.
import { beforeAll, describe, expect, it } from 'vitest';
import { analyzeMysql, type MysqlAnalyzeContext } from '../src/engines/mysql/analyze.js';
import { analyze, initAnalyzer } from '../src/engines/postgres/analyze.js';
import type { Analysis, StatementAnalysis } from '../src/engines/types.js';

beforeAll(() => initAnalyzer());

/** "verb:table" for every access, de-duplicated and sorted; `-` for no table. */
const accesses = (s: StatementAnalysis) => [...new Set(s.accesses.map((a) => `${a.verb}:${a.table ?? '-'}`))].sort();
const all = (a: Analysis) => [...new Set(a.statements.flatMap(accesses))].sort();
const kinds = (a: Analysis) => a.statements.map((s) => s.kind);

describe('Postgres: one statement, several actions', () => {
  const one = (sql: string) => {
    const a = analyze(sql);
    expect(a.error, sql).toBeNull();
    expect(a.statements, sql).toHaveLength(1);
    return a.statements[0];
  };

  it('chained data-modifying CTEs: archive, delete, then log, in one statement', () => {
    const s = one(`
      WITH moved AS (
        DELETE FROM orders WHERE status = 'cancelled' AND created_at < now() - interval '90 days' RETURNING *
      ), archived AS (
        INSERT INTO orders_archive SELECT * FROM moved RETURNING id
      )
      INSERT INTO audit_log (action, n) SELECT 'archive', count(*) FROM archived`);
    expect(s.kind).toBe('write');
    expect(accesses(s)).toEqual(['delete:orders', 'insert:audit_log', 'insert:orders_archive']);
    expect(s.flags).not.toContain('no_where');
  });

  it('a CTE that updates, read by a join with real tables', () => {
    const s = one(`
      WITH bumped AS (UPDATE products p SET price = price * 1.1 FROM suppliers s WHERE s.id = p.supplier_id AND s.region = 'EU' RETURNING p.id, p.price)
      SELECT b.id, b.price, c.name FROM bumped b JOIN categories c ON c.id = (SELECT category_id FROM products WHERE id = b.id)`);
    expect(accesses(s)).toEqual(['select:categories', 'select:products', 'select:suppliers', 'update:products']);
  });

  it('a recursive CTE that only reads stays a read', () => {
    const s = one(`
      WITH RECURSIVE tree AS (
        SELECT id, parent_id, 1 AS depth FROM categories WHERE parent_id IS NULL
        UNION ALL
        SELECT c.id, c.parent_id, t.depth + 1 FROM categories c JOIN tree t ON c.parent_id = t.id
      )
      SELECT * FROM tree ORDER BY depth`);
    expect(s.kind).toBe('read');
    expect(accesses(s)).toEqual(['select:categories']);
  });

  it('a write hidden three levels deep (CTE in a subquery in a UNION) is found', () => {
    const s = one(`
      SELECT id FROM customers
      UNION
      SELECT id FROM (SELECT * FROM (WITH gone AS (DELETE FROM sessions WHERE expires < now() RETURNING user_id) SELECT user_id AS id FROM gone) a) b`);
    expect(s.kind).toBe('write');
    expect(accesses(s)).toEqual(['delete:sessions', 'select:customers']);
  });

  it('UPDATE … FROM with a join, a correlated subquery and a sequence', () => {
    const s = one(`
      UPDATE orders o SET total_cents = sub.total, invoice_no = nextval('invoice_seq')
      FROM (SELECT order_id, sum(price_cents * qty) AS total FROM order_items GROUP BY order_id) sub
      WHERE sub.order_id = o.id AND EXISTS (SELECT 1 FROM customers c WHERE c.id = o.customer_id AND c.active)`);
    expect(accesses(s)).toEqual(['function:-', 'select:customers', 'select:order_items', 'update:orders']);
  });

  it('DELETE … USING reads the other tables and deletes from one', () => {
    const s = one('DELETE FROM order_items oi USING orders o, customers c WHERE oi.order_id = o.id AND o.customer_id = c.id AND c.deleted');
    expect(accesses(s)).toEqual(['delete:order_items', 'select:customers', 'select:orders']);
  });

  it('MERGE with insert, update and delete branches reads its source', () => {
    const s = one(`
      MERGE INTO inventory i USING (SELECT sku, sum(qty) AS qty FROM shipments GROUP BY sku) s ON i.sku = s.sku
      WHEN MATCHED AND i.qty + s.qty = 0 THEN DELETE
      WHEN MATCHED THEN UPDATE SET qty = i.qty + s.qty
      WHEN NOT MATCHED THEN INSERT (sku, qty) VALUES (s.sku, s.qty)`);
    expect(s.kind).toBe('write');
    expect(accesses(s)).toContain('merge:inventory');
    expect(accesses(s)).toContain('select:shipments');
  });

  it('INSERT … SELECT … ON CONFLICT DO UPDATE is an insert and an update, reading the source', () => {
    const s = one(`
      INSERT INTO daily_totals (day, total) SELECT date_trunc('day', created_at), sum(total_cents) FROM orders GROUP BY 1
      ON CONFLICT (day) DO UPDATE SET total = excluded.total`);
    expect(accesses(s)).toEqual(['insert:daily_totals', 'select:orders', 'update:daily_totals']);
  });

  it('a read that locks some tables but not others', () => {
    const s = one('SELECT * FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.id = 1 FOR UPDATE OF o');
    expect(s.kind).toBe('write');
    expect(accesses(s)).toContain('lock:orders');
  });

  it('a volatile function in a WHERE clause makes an otherwise-plain SELECT ask', () => {
    const s = one("SELECT * FROM orders WHERE id = (SELECT max(id) FROM orders) AND pg_notify('orders', id::text) IS NOT NULL");
    expect(s.kind).toBe('write');
    expect(accesses(s)).toEqual(['function:-', 'select:orders']);
  });

  it('an admin function inside a CTE inside EXPLAIN ANALYZE is still admin', () => {
    expect(one('EXPLAIN ANALYZE WITH x AS (SELECT pg_terminate_backend(pid) FROM pg_stat_activity) SELECT * FROM x').kind).toBe('admin');
  });

  it('plain EXPLAIN of a multi-write CTE only reads', () => {
    const s = one('EXPLAIN WITH d AS (DELETE FROM a RETURNING *) INSERT INTO b SELECT * FROM d');
    expect(s.kind).toBe('read');
  });

  it('EXPLAIN ANALYZE of the same statement runs both writes', () => {
    const s = one('EXPLAIN (ANALYZE, BUFFERS) WITH d AS (DELETE FROM a RETURNING *) INSERT INTO b SELECT * FROM d');
    expect(s.kind).toBe('write');
    expect(accesses(s)).toEqual(['delete:a', 'insert:b']);
  });

  it('CREATE TABLE AS from a query that deletes is DDL and a delete', () => {
    const s = one('CREATE TABLE snapshot AS WITH d AS (DELETE FROM queue RETURNING *) SELECT * FROM d');
    expect(s.kind).toBe('ddl');
    expect(accesses(s)).toContain('delete:queue');
    expect(accesses(s)).toContain('create:snapshot');
  });

  it('COPY of a data-modifying query to stdout is a write', () => {
    const s = one('COPY (WITH u AS (UPDATE jobs SET claimed = true WHERE NOT claimed RETURNING *) SELECT * FROM u) TO STDOUT');
    expect(s.kind).toBe('write');
    expect(accesses(s)).toContain('update:jobs');
  });

  it('keywords inside strings, comments, dollar quotes and identifiers are not statements', () => {
    const s = one(`
      SELECT 'DELETE FROM orders; DROP TABLE x' AS a, $q$; TRUNCATE y;$q$ AS b, "DROP TABLE z;" -- ; DELETE FROM w
      FROM /* ; UPDATE v SET x = 1; */ customers`);
    expect(s.kind).toBe('read');
    expect(accesses(s)).toEqual(['select:customers']);
  });
});

describe('Postgres: scripts of several statements', () => {
  it('a migration script: DDL, a backfill, an index and a grant, each classified on its own', () => {
    const a = analyze(`
      BEGIN;
      ALTER TABLE orders ADD COLUMN shipped_at timestamptz;
      UPDATE orders SET shipped_at = updated_at WHERE status = 'shipped';
      CREATE INDEX orders_shipped_at ON orders (shipped_at);
      GRANT SELECT ON orders TO reporting;
      COMMIT;`);
    expect(kinds(a)).toEqual(['session', 'ddl', 'write', 'ddl', 'admin', 'session']);
    expect(a.statements.map((s) => s.command)).toEqual(['BEGIN', 'ALTER TABLE', 'UPDATE', 'CREATE INDEX', 'GRANT', 'COMMIT']);
    expect(all(a)).toEqual(['admin:orders', 'alter:orders', 'create:orders', 'update:orders']);
  });

  it('read, write, read: the batch is as strict as its strictest statement', () => {
    const a = analyze("SELECT count(*) FROM orders; DELETE FROM orders WHERE status = 'test'; SELECT count(*) FROM orders");
    expect(kinds(a)).toEqual(['read', 'write', 'read']);
    expect(a.statements[1].text).toBe("DELETE FROM orders WHERE status = 'test'");
  });

  it('a sneaky tail after a harmless start is still seen', () => {
    const a = analyze("SELECT 1; SET LOCAL statement_timeout = '1s'; SET ROLE postgres; DROP TABLE customers CASCADE");
    expect(kinds(a)).toEqual(['read', 'session', 'admin', 'ddl']);
    expect(a.statements[3].flags).toContain('destructive');
  });

  it('a savepoint dance around two writes', () => {
    const a = analyze(`
      BEGIN;
      INSERT INTO payments (order_id, amount) VALUES (1, 100);
      SAVEPOINT before_refund;
      UPDATE orders SET status = 'refunded' WHERE id = 1;
      ROLLBACK TO SAVEPOINT before_refund;
      COMMIT`);
    expect(kinds(a)).toEqual(['session', 'write', 'session', 'write', 'session', 'session']);
    expect(all(a)).toEqual(['insert:payments', 'update:orders']);
  });

  it('PREPARE then EXECUTE in the same batch: EXECUTE carries the prepared write', () => {
    const a = analyze('PREPARE purge (int) AS DELETE FROM sessions WHERE user_id = $1; EXECUTE purge(42)');
    expect(kinds(a)).toEqual(['session', 'write']);
    expect(accesses(a.statements[1])).toEqual(['delete:sessions']);
  });

  it('re-preparing a name the session already has does not change what EXECUTE runs (Postgres refuses it)', () => {
    const prepared = new Map([['p', analyze('DELETE FROM orders').statements[0]]]);
    const a = analyze('PREPARE p AS SELECT 1; EXECUTE p', { prepared });
    expect(kinds(a)).toEqual(['session', 'write']);
  });

  it('a syntax error anywhere makes the whole batch admin (nothing is half-understood)', () => {
    const a = analyze('SELECT 1; DELETE FROM orders WHERE; SELECT 2');
    expect(a.error).toMatch(/syntax error/);
    expect(kinds(a)).toEqual(['admin']);
  });
});

describe('MySQL: one statement, several actions', () => {
  const ctx: MysqlAnalyzeContext = { database: 'shop', databaseAliases: [], catalog: { functions: new Set(['shop.bump']), udfs: new Set() } };
  const one = (sql: string) => {
    const a = analyzeMysql(sql, ctx);
    expect(a.statements, sql).toHaveLength(1);
    return a.statements[0];
  };

  it('multi-table UPDATE with a derived table and a subquery in SET', () => {
    const s = one(`
      UPDATE orders o
        JOIN (SELECT order_id, SUM(price * qty) AS total FROM order_items GROUP BY order_id) t ON t.order_id = o.id
        JOIN customers c ON c.id = o.customer_id
      SET o.total = t.total, c.lifetime = c.lifetime + t.total, o.region = (SELECT region FROM zips z WHERE z.zip = c.zip)
      WHERE o.status = 'open'`);
    expect(s.kind).toBe('write');
    // Tables joined at the top may be written; a derived table's source is only read.
    expect(accesses(s)).toEqual(['select:order_items', 'select:zips', 'update:customers', 'update:orders']);
  });

  it('WITH … DELETE (MySQL 8 CTE before a DELETE) deletes from the target', () => {
    const s = one('WITH stale AS (SELECT id FROM sessions WHERE expires < NOW()) DELETE FROM sessions WHERE id IN (SELECT id FROM stale)');
    expect(s.kind).toBe('write');
    expect(accesses(s)).toContain('delete:sessions');
    expect(accesses(s)).not.toContain('select:stale');
  });

  it('INSERT … SELECT with a join, ON DUPLICATE KEY UPDATE and a stored function', () => {
    const s = one(`
      INSERT INTO daily_totals (day, total)
      SELECT DATE(o.created_at), SUM(o.total) FROM orders o JOIN customers c ON c.id = o.customer_id WHERE shop.bump(c.id) > 0 GROUP BY 1
      ON DUPLICATE KEY UPDATE total = VALUES(total)`);
    expect(accesses(s)).toEqual(['function:-', 'insert:daily_totals', 'select:customers', 'select:orders', 'update:daily_totals']);
  });

  it('REPLACE … SELECT deletes and inserts the target, reads the source', () => {
    expect(accesses(one('REPLACE INTO cache (k, v) SELECT k, v FROM staging WHERE ready'))).toEqual(['delete:cache', 'insert:cache', 'select:staging']);
  });

  it('a SELECT that reads under a lock across a join and a subquery', () => {
    const s = one('SELECT * FROM jobs j JOIN workers w ON w.id = j.worker WHERE j.id = (SELECT MIN(id) FROM jobs WHERE NOT claimed) FOR UPDATE SKIP LOCKED');
    expect(s.kind).toBe('write');
    expect(accesses(s)).toContain('lock:jobs');
  });

  it('an executable comment that hides a second statement is split out and seen', () => {
    // MySQL runs what /*! … */ contains, so this is really two statements.
    const a = analyzeMysql('SELECT * FROM orders /*!50000 ; DELETE FROM orders */', ctx);
    expect(kinds(a)).toEqual(['read', 'write']);
    expect(accesses(a.statements[1])).toEqual(['delete:orders']);
  });

  it('keywords inside strings, comments and backticks are not statements', () => {
    const s = one("SELECT 'DELETE FROM orders; DROP TABLE x', `DROP TABLE y;` FROM customers -- ; TRUNCATE z\n# ; DELETE FROM w\n/* ; UPDATE v SET a = 1 */");
    expect(s.kind).toBe('read');
    expect(accesses(s)).toEqual(['select:customers']);
  });
});

describe('MySQL: scripts of several statements', () => {
  const ctx: MysqlAnalyzeContext = { database: 'shop', databaseAliases: [] };

  it('a migration script is classified statement by statement', () => {
    const a = analyzeMysql(
      `START TRANSACTION;
       ALTER TABLE orders ADD COLUMN shipped_at DATETIME NULL;
       UPDATE orders SET shipped_at = updated_at WHERE status = 'shipped';
       CREATE INDEX orders_shipped_at ON orders (shipped_at);
       GRANT SELECT ON shop.orders TO 'reporting'@'%';
       COMMIT;`,
      ctx,
    );
    expect(kinds(a)).toEqual(['session', 'ddl', 'write', 'ddl', 'admin', 'session']);
    expect(all(a)).toContain('update:orders');
  });

  it('read, write, read with a semicolon inside a string in the middle', () => {
    const a = analyzeMysql("SELECT COUNT(*) FROM orders; UPDATE orders SET note = 'a;b' WHERE id = 1; SELECT note FROM orders WHERE id = 1", ctx);
    expect(kinds(a)).toEqual(['read', 'write', 'read']);
    expect(a.statements[1].text).toBe("UPDATE orders SET note = 'a;b' WHERE id = 1");
  });

  it('a sneaky tail: harmless SET then a privilege change and a DROP', () => {
    const a = analyzeMysql("SET NAMES utf8mb4; SET @x = 1; SET GLOBAL read_only = 0; DROP TABLE customers", ctx);
    expect(kinds(a).slice(-2)).toEqual(['admin', 'ddl']);
  });

  it('PREPARE from a string then EXECUTE: the EXECUTE is the write', () => {
    const a = analyzeMysql("PREPARE p FROM 'DELETE FROM sessions WHERE user_id = ?'; SET @u = 42; EXECUTE p USING @u", ctx);
    expect(a.statements.at(-1)!.kind).toBe('write');
    expect(accesses(a.statements.at(-1)!)).toEqual(['delete:sessions']);
  });
});
