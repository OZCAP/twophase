import { describe, expect, it } from 'vitest';
import { analyzeMysql, type MysqlAnalyzeContext } from '../src/engines/mysql/analyze.js';
import type { RoutineCatalog } from '../src/engines/mysql/functions.js';
import { lex } from '../src/engines/mysql/lexer.js';
import type { StatementAnalysis } from '../src/engines/types.js';

const catalog: RoutineCatalog = { functions: new Set(['bump_counter', 'shop.bump_counter']), udfs: new Set(['sys_exec_udf']) };
const base: MysqlAnalyzeContext = { database: 'shop', databaseAliases: ['shop-proxy'], catalog };

const one = (sql: string, ctx: MysqlAnalyzeContext = base) => {
  const a = analyzeMysql(sql, ctx);
  expect(a.statements, sql).toHaveLength(1);
  return a.statements[0];
};
/** "verb:table" for every access, sorted; `-` for no table. */
const accesses = (s: StatementAnalysis) => s.accesses.map((a) => `${a.verb}:${a.table ?? '-'}`).sort();

describe('kinds', () => {
  const cases: [string, StatementAnalysis['kind']][] = [
    // reads
    ['SELECT * FROM orders o JOIN shop.customers c ON c.id = o.customer_id WHERE o.total > 100', 'read'],
    ['SELECT count(*), lower(email) FROM customers GROUP BY 2', 'read'],
    ['SELECT * FROM orders PARTITION (p0) USE INDEX (idx) WHERE id = 1', 'read'],
    ["SELECT * FROM t, JSON_TABLE('[1]', '$[*]' COLUMNS (a INT PATH '$')) jt", 'read'],
    ['WITH recent AS (SELECT * FROM orders) SELECT * FROM recent', 'read'],
    ['TABLE orders', 'read'],
    ['SHOW TABLES', 'read'],
    ['SHOW CREATE TABLE orders', 'read'],
    ['SHOW FULL COLUMNS FROM orders', 'read'],
    ['DESCRIBE orders', 'read'],
    ['EXPLAIN SELECT * FROM orders', 'read'],
    ['EXPLAIN DELETE FROM orders', 'read'],
    ['EXPLAIN FORMAT=JSON UPDATE orders SET a = 1', 'read'],
    ['SELECT SLEEP(0), RAND(), UUID() FROM orders', 'read'],
    ['SELECT * FROM orders INTO @x', 'read'],
    ['HANDLER orders OPEN', 'read'],
    // session: touches no data
    ['SELECT 1', 'session'],
    ['SELECT @@version_comment LIMIT 1', 'session'],
    ['SELECT DATABASE(), NOW(), CONNECTION_ID()', 'session'],
    ['SHOW VARIABLES LIKE "sql_mode"', 'session'],
    ['SHOW WARNINGS', 'session'],
    ['SET NAMES utf8mb4', 'session'],
    ["SET NAMES 'utf8mb4' COLLATE 'utf8mb4_0900_ai_ci'", 'session'],
    ['SET autocommit = 0', 'session'],
    ["SET @@session.time_zone = '+00:00', @x := 5", 'session'],
    ['SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED', 'session'],
    ['SET character_set_results = NULL', 'session'],
    ['START TRANSACTION READ ONLY', 'session'],
    ['BEGIN', 'session'],
    ['COMMIT', 'session'],
    ['ROLLBACK TO SAVEPOINT a', 'session'],
    ['SAVEPOINT a', 'session'],
    ['UNLOCK TABLES', 'session'],
    ['USE shop', 'session'],
    ['USE `shop-proxy`', 'session'],
    ['DO SLEEP(0)', 'session'],
    ['DEALLOCATE PREPARE s', 'session'],
    // writes
    ['INSERT INTO orders (customer_id, total) VALUES (1, 100)', 'write'],
    ['INSERT INTO orders(customer_id) VALUES (1)', 'write'],
    ['INSERT orders SET total = 1', 'write'],
    ['REPLACE INTO orders VALUES (1)', 'write'],
    ["UPDATE orders SET status = 'refunded' WHERE id = 1", 'write'],
    ['DELETE FROM orders WHERE id = 1', 'write'],
    ['SELECT * FROM orders FOR UPDATE', 'write'],
    ['SELECT * FROM orders WHERE id = 1 LOCK IN SHARE MODE', 'write'],
    ['SELECT * FROM orders FOR SHARE SKIP LOCKED', 'write'],
    ['EXPLAIN ANALYZE SELECT * FROM orders FOR UPDATE', 'write'],
    ['ANALYZE DELETE FROM orders', 'write'],
    ['LOCK TABLES orders WRITE', 'write'],
    ['CALL refund(1)', 'write'],
    ['TRUNCATE TABLE orders', 'write'],
    ["SELECT GET_LOCK('x', 1)", 'write'],
    ['DO RELEASE_ALL_LOCKS()', 'write'],
    ['SELECT bump_counter()', 'write'],
    ['SELECT other.fn(1) FROM orders', 'write'],
    ['SELECT NEXT VALUE FOR seq', 'write'],
    ['SET @x = bump_counter()', 'write'],
    ['WITH c AS (SELECT id FROM a) UPDATE b JOIN c ON b.id = c.id SET b.x = 1', 'write'],
    // ddl
    ['CREATE TABLE t (id INT PRIMARY KEY)', 'ddl'],
    ['CREATE TEMPORARY TABLE IF NOT EXISTS t (id INT)', 'ddl'],
    ['CREATE TABLE t AS SELECT * FROM orders', 'ddl'],
    ['CREATE TABLE t LIKE orders', 'ddl'],
    ['CREATE UNIQUE INDEX i ON orders (email)', 'ddl'],
    ['CREATE OR REPLACE VIEW v AS SELECT * FROM orders', 'ddl'],
    ['CREATE TRIGGER trg BEFORE INSERT ON orders FOR EACH ROW SET NEW.total = 0', 'ddl'],
    ['CREATE PROCEDURE p() SELECT 1', 'ddl'],
    ['ALTER TABLE orders ADD COLUMN note TEXT', 'ddl'],
    ['DROP TABLE IF EXISTS a, b', 'ddl'],
    ['DROP INDEX i ON orders', 'ddl'],
    ['RENAME TABLE a TO b, c TO d', 'ddl'],
    // admin
    ['GRANT SELECT ON shop.* TO bob', 'admin'],
    ['FLUSH PRIVILEGES', 'admin'],
    ['KILL QUERY 12', 'admin'],
    ["SELECT * FROM orders INTO OUTFILE '/tmp/x'", 'admin'],
    ["SELECT LOAD_FILE('/etc/passwd')", 'admin'],
    ["LOAD DATA INFILE '/tmp/x' INTO TABLE orders", 'admin'],
    ["LOAD DATA LOCAL INFILE '/tmp/x' INTO TABLE orders", 'admin'],
    ['SET GLOBAL max_connections = 1', 'admin'],
    ['SET @@global.read_only = 0', 'admin'],
    ["SET SESSION sql_mode = 'ANSI_QUOTES'", 'admin'],
    ['SET sql_log_bin = 0', 'admin'],
    ['SET foreign_key_checks = 0', 'admin'],
    ['SET NAMES gbk', 'admin'],
    ['SET character_set_client = sjis', 'admin'],
    ["SET PASSWORD = 'x'", 'admin'],
    ['SET ROLE ALL', 'admin'],
    ['CREATE DATABASE other', 'admin'],
    ['DROP DATABASE shop', 'admin'],
    ["CREATE USER 'x'@'%' IDENTIFIED BY 'y'", 'admin'],
    ["CREATE DEFINER = 'root'@'%' VIEW v AS SELECT 1", 'admin'],
    ['CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO DELETE FROM orders', 'admin'],
    ["CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so'", 'admin'],
    ['INSTALL PLUGIN x SONAME "x.so"', 'admin'],
    ['USE mysql', 'admin'],
    ['XA START "x"', 'admin'],
    ['ANALYZE TABLE orders', 'admin'],
    ['OPTIMIZE TABLE orders', 'admin'],
    ['SHUTDOWN', 'admin'],
    ['CHANGE REPLICATION SOURCE TO SOURCE_HOST = "x"', 'admin'],
    ['START REPLICA', 'admin'],
    ['LOCK INSTANCE FOR BACKUP', 'admin'],
    ['BEGIN NOT ATOMIC DELETE FROM orders; END', 'admin'],
    ['PREPARE s FROM @sql', 'admin'],
    ['EXECUTE unknown_stmt', 'admin'],
    ['SELECT sys_exec_udf("id")', 'admin'],
    ['frobnicate the database', 'admin'],
    ["SELECT 'unterminated", 'admin'],
  ];
  it.each(cases)('%s → %s', (sql, kind) => {
    expect(one(sql).kind).toBe(kind);
  });
});

describe('tables and verbs', () => {
  it('names a join, normalizing the current database qualifier and case', () => {
    expect(accesses(one('SELECT * FROM Orders o JOIN shop.customers c ON c.id = o.cid JOIN other.t ON 1'))).toEqual([
      'select:customers',
      'select:orders',
      'select:other.t',
    ]);
  });

  it('comma joins, derived tables and subqueries', () => {
    expect(accesses(one('SELECT * FROM a, b x, (SELECT * FROM c) d WHERE a.id IN (SELECT id FROM e)'))).toEqual([
      'select:a',
      'select:b',
      'select:c',
      'select:e',
    ]);
  });

  it('CTE names are not tables', () => {
    expect(accesses(one('WITH x AS (SELECT * FROM a), y (n) AS (SELECT 1) SELECT * FROM x JOIN y JOIN b'))).toEqual(['select:a', 'select:b']);
  });

  it('does not take EXTRACT(… FROM col) or CONVERT(… USING cs) for tables', () => {
    expect(accesses(one('SELECT EXTRACT(YEAR FROM created), TRIM(LEADING 0 FROM x), CONVERT(y USING utf8mb4) FROM orders'))).toEqual(['select:orders']);
  });

  it('INSERT … SELECT writes the target and reads the source', () => {
    expect(accesses(one('INSERT INTO archive (id) SELECT id FROM orders WHERE old'))).toEqual(['insert:archive', 'select:orders']);
  });

  it('ON DUPLICATE KEY UPDATE is an update too; REPLACE is a delete too', () => {
    expect(accesses(one('INSERT INTO t (id) VALUES (1) ON DUPLICATE KEY UPDATE id = VALUES(id)'))).toEqual(['insert:t', 'update:t']);
    expect(accesses(one('REPLACE INTO t (id) VALUES (1)'))).toEqual(['delete:t', 'insert:t']);
  });

  it('multi-table UPDATE writes every table in the UPDATE clause, reads subquery tables', () => {
    const s = one('UPDATE a JOIN b ON a.id = b.id SET b.x = 1 WHERE a.y IN (SELECT y FROM c)');
    expect(accesses(s)).toEqual(['select:c', 'update:a', 'update:b']);
    expect(s.flags).not.toContain('no_where');
    expect(one('UPDATE a, b SET a.x = b.x').flags).toContain('no_where');
  });

  it('multi-table DELETE only deletes from the listed tables (resolving aliases)', () => {
    expect(accesses(one('DELETE o FROM orders o JOIN customers c ON c.id = o.cid WHERE c.banned'))).toEqual(['delete:orders', 'select:customers']);
    expect(accesses(one('DELETE FROM a, b USING a JOIN b JOIN c WHERE a.id = b.id'))).toEqual(['delete:a', 'delete:b', 'select:c']);
    expect(accesses(one('DELETE a.* FROM a JOIN b'))).toEqual(['delete:a', 'select:b']);
  });

  it('flags DELETE without WHERE', () => {
    expect(one('DELETE FROM orders').flags).toContain('no_where');
    expect(one('DELETE FROM orders WHERE id = 1').flags).not.toContain('no_where');
  });

  it('FOR UPDATE locks every table it reads', () => {
    expect(accesses(one('SELECT * FROM a JOIN b ON a.id = b.id FOR UPDATE'))).toEqual(['lock:a', 'lock:b']);
  });

  it('LOCK TABLES names each table', () => {
    expect(accesses(one('LOCK TABLES a READ, b AS x WRITE, shop.c READ LOCAL'))).toEqual(['lock:a', 'lock:b', 'lock:c']);
  });

  it('plain EXPLAIN reads what the statement would write', () => {
    expect(accesses(one('EXPLAIN DELETE FROM orders WHERE id = 1'))).toEqual(['select:orders']);
  });

  it('EXPLAIN ANALYZE is what it runs', () => {
    const s = one('EXPLAIN ANALYZE DELETE FROM orders WHERE id = 1');
    expect(accesses(s)).toEqual(['delete:orders']);
    expect(s.flags).toContain('explain_analyze');
  });

  it('DDL targets', () => {
    expect(accesses(one('CREATE TABLE t AS SELECT * FROM orders'))).toEqual(['create:t', 'select:orders']);
    expect(accesses(one('CREATE INDEX i ON orders (x)'))).toEqual(['create:orders']);
    expect(accesses(one('ALTER TABLE a RENAME TO b'))).toEqual(['alter:a', 'alter:b']);
    expect(accesses(one('RENAME TABLE a TO b, c TO d'))).toEqual(['alter:a', 'alter:b', 'alter:c', 'alter:d']);
    expect(accesses(one('DROP TABLE a, shop.b'))).toEqual(['drop:a', 'drop:b']);
    expect(one('DROP TABLE a').flags).toContain('destructive');
    expect(accesses(one('TRUNCATE orders'))).toEqual(['truncate:orders']);
  });

  it('SHOW COLUMNS FROM t FROM db', () => {
    expect(accesses(one('SHOW COLUMNS FROM t FROM other'))).toEqual(['select:other.t']);
  });
});

describe('statements and splitting', () => {
  it('splits on semicolons outside quotes and comments', () => {
    const a = analyzeMysql("SELECT ';' FROM a; -- x; DELETE\nUPDATE b SET c = 'it''s; \\'fine'; # ; DROP\n/* ; */ SELECT 1");
    expect(a.statements.map((s) => s.command)).toEqual(['SELECT', 'UPDATE', 'SELECT']);
    expect(a.statements[1].text).toBe("UPDATE b SET c = 'it''s; \\'fine'");
  });

  it('a backslash-escaped quote does not end the string (unless NO_BACKSLASH_ESCAPES)', () => {
    const sql = "SELECT * FROM t WHERE a = 'x\\'; DROP TABLE t; -- '";
    expect(analyzeMysql(sql).statements.map((s) => s.command)).toEqual(['SELECT']);
    expect(analyzeMysql(sql, { noBackslashEscapes: true }).statements.map((s) => s.command)).toEqual(['SELECT', 'DROP TABLE']);
  });

  it('double quotes are strings, or identifiers with ANSI_QUOTES', () => {
    expect(accesses(one('SELECT * FROM "orders"', { ansiQuotes: true }))).toEqual(['select:orders']);
    expect(one('SELECT "orders"').kind).toBe('session');
  });

  it('classifies what executable comments contain', () => {
    expect(one('SELECT 1 /*!50000 , (SELECT secret FROM vault) */').kind).toBe('read');
    expect(one('/*!40101 SET NAMES utf8mb4 */').kind).toBe('session');
    const a = analyzeMysql('SELECT 1 /*! ; DROP TABLE orders */');
    expect(a.statements.map((s) => s.kind)).toEqual(['session', 'ddl']);
    expect(one('/*M!100100 DELETE FROM orders */').kind).toBe('write');
    expect(one('SELECT /*+ MAX_EXECUTION_TIME(1000) */ * FROM orders').kind).toBe('read');
  });

  it('`--x` is not a comment, `-- x` is', () => {
    expect(analyzeMysql('SELECT 1 --1\n; DELETE FROM t').statements.map((s) => s.kind)).toEqual(['session', 'write']);
    expect(analyzeMysql('SELECT 1 -- ; DELETE FROM t').statements).toHaveLength(1);
  });

  it('a stored program with a multi-statement body is admin and swallows the rest', () => {
    const a = analyzeMysql('CREATE PROCEDURE p() BEGIN SELECT begin FROM t; END; DROP DATABASE x');
    expect(a.statements).toHaveLength(1);
    expect(a.statements[0].kind).toBe('admin');
    expect(a.statements[0].flags).toContain('compound_statement');
  });

  it('PREPARE remembers its statement; EXECUTE uses it', () => {
    const prep = one("PREPARE del FROM 'DELETE FROM orders WHERE id = ?'");
    expect(prep.kind).toBe('session');
    expect(prep.prepared?.name).toBe('del');
    const exec = one('EXECUTE del USING @id', { ...base, prepared: new Map([['del', prep.prepared!.analysis]]) });
    expect(exec.kind).toBe('write');
    expect(accesses(exec)).toEqual(['delete:orders']);
  });

  it('MariaDB SET STATEMENT … FOR classifies the inner statement', () => {
    expect(one('SET STATEMENT max_statement_time = 1 FOR DELETE FROM orders').kind).toBe('write');
    expect(one('SET STATEMENT sql_mode = "" FOR SELECT 1').kind).toBe('admin');
  });

  it('unknown functions remain opaque with or without a catalog', () => {
    expect(one('SELECT mystery(1)', { database: 'shop' }).kind).toBe('write');
    expect(one('SELECT mystery(1)', base).kind).toBe('write');
    expect(one('SELECT mystery(1)', base).flags).toContain('opaque_function');
    expect(one('SELECT lower(x) FROM t', { database: 'shop' }).kind).toBe('read');
  });

  it('lexes the usual literal forms', () => {
    const t = lex("SELECT X'0A', _utf8mb4'x', 0x1F, 1.5e3, 1abc, @`v`, @@global.x, ?");
    expect(t.map((x) => x.type)).toEqual(['word', 'word', 'string', 'punct', 'word', 'string', 'punct', 'number', 'punct', 'number', 'punct', 'word', 'punct', 'var', 'punct', 'sysvar', 'punct', 'param']);
  });
});
