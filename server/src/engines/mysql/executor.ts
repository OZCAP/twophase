import mysql from 'mysql2';
import type { DatabaseConfig } from '../../store.js';
import { capResultSize, jsonCell, uniqueNames } from '../results.js';
import { QueryError, type Analysis, type Estimate, type Executor, type StatementAnalysis, type StatementResult, type TableInfo } from '../types.js';
import { analyzeMysql } from './analyze.js';
import type { RoutineCatalog } from './functions.js';

const CATALOG_TTL_MS = 5 * 60_000;

/** mysql2 column type codes → names. */
const TYPE_NAMES: Record<number, string> = {
  0: 'decimal', 1: 'tinyint', 2: 'smallint', 3: 'int', 4: 'float', 5: 'double', 6: 'null', 7: 'timestamp', 8: 'bigint',
  9: 'mediumint', 10: 'date', 11: 'time', 12: 'datetime', 13: 'year', 15: 'varchar', 16: 'bit', 245: 'json', 246: 'decimal',
  247: 'enum', 248: 'set', 249: 'blob', 250: 'blob', 251: 'blob', 252: 'blob', 253: 'varchar', 254: 'char', 255: 'geometry',
};
const BINARY_CHARSET = 63;

/** What the analyzer needs to read SQL the way this server will. */
interface ServerContext {
  catalog: RoutineCatalog | null;
  ansiQuotes: boolean;
  noBackslashEscapes: boolean;
  mariadb: boolean;
}

type Conn = mysql.PoolConnection;

export function mysqlSsl(db: Pick<DatabaseConfig, 'sslmode' | 'host'>): mysql.SslOptions | undefined {
  if (db.sslmode === 'disable') return undefined;
  if (db.sslmode === 'verify-full') return { rejectUnauthorized: true };
  return { rejectUnauthorized: false };
}

function toQueryError(err: unknown): QueryError {
  if (err instanceof QueryError) return err;
  const e = err as { message?: string; sqlMessage?: string; sqlState?: string; code?: string; errno?: number };
  const message = e.sqlMessage ?? e.message ?? String(err);
  return new QueryError(e.errno ? `${message} (${e.code ?? e.errno})` : message, typeof e.sqlState === 'string' && /^[0-9A-Z]{5}$/.test(e.sqlState) ? e.sqlState : null);
}

function query<T = any>(conn: Conn | mysql.Pool, sql: string, values?: unknown[]): Promise<T> {
  return new Promise((resolve, reject) => conn.query(sql, values, (err, rows) => (err ? reject(err) : resolve(rows as T))));
}

/**
 * MySQL / MariaDB executor (mysql2). Reads run in `START TRANSACTION READ ONLY`, so the server
 * refuses table writes the classifier might have missed; approved writes run in one transaction
 * (DDL commits implicitly, as MySQL always does).
 */
export class MysqlExecutor implements Executor {
  readonly placeholder = '?';
  private pool: mysql.Pool | null = null;
  private resolvedSsl: Promise<mysql.SslOptions | undefined> | null = null;
  private server: { at: number; value: Promise<ServerContext> } | null = null;

  constructor(readonly db: DatabaseConfig) {}

  private options(ssl: mysql.SslOptions | undefined): mysql.PoolOptions {
    return {
      host: this.db.host,
      port: this.db.port,
      user: this.db.user,
      password: this.db.password,
      database: this.db.database,
      ssl,
      charset: 'utf8mb4',
      connectTimeout: 10_000,
      supportBigNumbers: true,
      bigNumberStrings: true,
      dateStrings: true,
      multipleStatements: false,
      connectAttributes: { program_name: 'twophase' },
    };
  }

  private ssl(): Promise<mysql.SslOptions | undefined> {
    return (this.resolvedSsl ??= (async () => {
      const ssl = mysqlSsl(this.db);
      if (this.db.sslmode !== 'prefer') return ssl;
      // "prefer": TLS if the server offers it, else plain.
      const probe = mysql.createConnection(this.options(ssl));
      try {
        await new Promise<void>((resolve, reject) => probe.connect((err) => (err ? reject(err) : resolve())));
        return ssl;
      } catch (err) {
        if (/does not support secure connection/i.test(String((err as Error).message))) return undefined;
        throw err;
      } finally {
        probe.destroy();
      }
    })().catch((err) => {
      this.resolvedSsl = null;
      throw err;
    }));
  }

  private async getPool(): Promise<mysql.Pool> {
    if (this.pool) return this.pool;
    const ssl = await this.ssl();
    this.pool ??= mysql.createPool({ ...this.options(ssl), connectionLimit: 5, maxIdle: 2, idleTimeout: 60_000 });
    return this.pool;
  }

  private async withConn<T>(fn: (c: Conn) => Promise<T>, discardAfter = false): Promise<T> {
    const pool = await this.getPool();
    const conn = await new Promise<Conn>((resolve, reject) => pool.getConnection((err, c) => (err ? reject(toQueryError(err)) : resolve(c))));
    let broken = discardAfter;
    try {
      return await fn(conn);
    } catch (err) {
      await query(conn, 'ROLLBACK').catch(() => (broken = true));
      throw toQueryError(err);
    } finally {
      if (broken) conn.destroy();
      else conn.release();
    }
  }

  /** Stored functions, loadable UDFs and sql_mode, cached for 5 minutes (reset after DDL). */
  private serverContext(): Promise<ServerContext> {
    if (this.server && Date.now() - this.server.at < CATALOG_TTL_MS) return this.server.value;
    const value = this.withConn(async (c) => {
      const [mode] = await query<{ mode: string; version: string }[]>(c, 'SELECT @@SESSION.sql_mode AS mode, VERSION() AS version');
      const modes = String(mode.mode).toUpperCase().split(',');
      let catalog: RoutineCatalog | null = null;
      try {
        const routines = await query<{ s: string; n: string }[]>(
          c,
          "SELECT LOWER(ROUTINE_SCHEMA) AS s, LOWER(ROUTINE_NAME) AS n FROM information_schema.ROUTINES WHERE ROUTINE_TYPE = 'FUNCTION'",
        );
        const db = this.db.database.toLowerCase();
        const functions = new Set<string>();
        for (const r of routines) {
          functions.add(`${r.s}.${r.n}`);
          if (r.s === db) functions.add(r.n);
        }
        const udfs = new Set<string>();
        for (const sql of ['SELECT LOWER(UDF_NAME) AS n FROM performance_schema.user_defined_functions', 'SELECT LOWER(name) AS n FROM mysql.func']) {
          const rows = await query<{ n: string }[]>(c, sql).catch(() => []);
          for (const r of rows) udfs.add(r.n);
        }
        catalog = { functions, udfs };
      } catch {
        catalog = null;
      }
      return { catalog, ansiQuotes: modes.includes('ANSI_QUOTES'), noBackslashEscapes: modes.includes('NO_BACKSLASH_ESCAPES'), mariadb: /mariadb/i.test(mode.version) };
    }).catch((): ServerContext => ({ catalog: null, ansiQuotes: false, noBackslashEscapes: false, mariadb: this.db.engine === 'mariadb' }));
    this.server = { at: Date.now(), value };
    return value;
  }

  invalidateCatalog() {
    this.server = null;
  }

  async analyze(sql: string): Promise<Analysis> {
    const ctx = await this.serverContext();
    return analyzeMysql(sql, { database: this.db.database, databaseAliases: [this.db.slug], ...ctx });
  }

  tableName(t: TableInfo): string {
    const name = t.name.toLowerCase();
    return t.schema.toLowerCase() === this.db.database.toLowerCase() ? name : `${t.schema.toLowerCase()}.${name}`;
  }

  /** Session statement timeout. MySQL's max_execution_time only covers SELECT; a watchdog KILL covers the rest. */
  private async limitTime(c: Conn, ms: number) {
    const { mariadb } = await this.serverContext();
    await query(c, mariadb ? `SET SESSION max_statement_time = ${ms / 1000}` : `SET SESSION max_execution_time = ${ms}`);
  }

  private watchdog(c: Conn, ms: number): () => void {
    const timer = setTimeout(() => {
      void this.getPool().then((pool) => query(pool, `KILL QUERY ${Number(c.threadId)}`).catch(() => {}));
    }, ms + 500);
    return () => clearTimeout(timer);
  }

  async run(statements: StatementAnalysis[], opts: { readOnly: boolean; params?: unknown[]; maxRows: number }): Promise<StatementResult[]> {
    const timeout = Math.max(1, Math.round(this.db.statementTimeoutMs));
    // Anything but a plain read may leave session state behind (temporary tables, locks): don't reuse that connection.
    const discard = statements.some((s) => s.kind !== 'read' && s.kind !== 'session');
    const results = await this.withConn(async (c) => {
      await this.limitTime(c, timeout);
      await query(c, opts.readOnly ? 'START TRANSACTION READ ONLY' : 'START TRANSACTION');
      const out: StatementResult[] = [];
      const stop = this.watchdog(c, timeout);
      try {
        for (const s of statements) out.push(await this.runOne(c, s, opts.params, opts.maxRows));
      } finally {
        stop();
      }
      await query(c, opts.readOnly ? 'ROLLBACK' : 'COMMIT');
      return out;
    }, discard);
    if (statements.some((s) => s.kind === 'ddl')) this.invalidateCatalog();
    return capResultSize(results);
  }

  /** Streams one statement's rows, keeping the first maxRows (+1 to know it was truncated). */
  private runOne(c: Conn, s: StatementAnalysis, params: unknown[] | undefined, maxRows: number): Promise<StatementResult> {
    return new Promise((resolve, reject) => {
      const options = { sql: s.text, rowsAsArray: true };
      const cmd = params?.length ? c.execute(options, params as mysql.ExecuteValues[]) : c.query(options);
      let fields: mysql.FieldPacket[] | null = null;
      let rows: unknown[][] = [];
      let total = 0;
      let affected: number | null = null;
      let sets = 0;
      cmd.on('fields', (f: mysql.FieldPacket[]) => {
        // Only the first result set is returned (CALL may produce more).
        sets++;
        if (sets === 1) fields = f;
      });
      cmd.on('result', (row: unknown) => {
        if (Array.isArray(row)) {
          if (sets !== 1) return;
          total++;
          if (rows.length <= maxRows) rows.push(row);
        } else if (row && typeof row === 'object' && 'affectedRows' in row) {
          affected ??= Number((row as { affectedRows: number }).affectedRows);
        }
      });
      cmd.on('error', (err: unknown) => reject(toQueryError(err)));
      cmd.on('end', () => {
        const f = (fields ?? []) as (mysql.FieldPacket & { columnType?: number; characterSet?: number })[];
        const names = uniqueNames(f.map((x) => x.name));
        const truncated = rows.length > maxRows;
        rows = rows.slice(0, maxRows);
        resolve({
          command: s.command,
          rowCount: fields ? total : affected,
          columns: f.map((x, i) => {
            const t = TYPE_NAMES[x.columnType ?? -1] ?? String(x.columnType);
            return { name: names[i], type: t === 'blob' && x.characterSet !== BINARY_CHARSET ? 'text' : t };
          }),
          rows: rows.map((r) => Object.fromEntries(names.map((n, i) => [n, jsonCell(r[i])]))),
          truncated,
        });
      });
    });
  }

  async estimate(statements: StatementAnalysis[], params?: unknown[]): Promise<Estimate> {
    const writes = statements.filter((s) => s.kind === 'write' && /^(UPDATE|DELETE|INSERT|REPLACE)/.test(s.command));
    if (writes.length === 0) return { rows: null, plan: null, error: null };
    // MySQL may evaluate constant expressions while planning: never plan a statement that calls stored functions.
    if (writes.some((s) => s.accesses.some((a) => a.verb === 'function' || a.op === 'admin'))) return { rows: null, plan: null, error: null };
    try {
      return await this.withConn(async (c) => {
        // EXPLAIN UPDATE is refused in a READ ONLY transaction; plan inside one that is rolled back instead.
        await this.limitTime(c, 2000);
        await query(c, 'START TRANSACTION');
        let rows: number | null = null;
        const plans: string[] = [];
        for (const s of writes) {
          const values = writes.length === 1 ? params : undefined;
          const out = values?.length
            ? await new Promise<any[]>((res, rej) => c.execute(`EXPLAIN ${s.text}`, values as mysql.ExecuteValues[], (e, r) => (e ? rej(e) : res(r as any[]))))
            : await query<any[]>(c, `EXPLAIN ${s.text}`);
          const target = out[0];
          if (!target) continue;
          const est = target.rows === null || target.rows === undefined ? null : Math.round((Number(target.rows) * Number(target.filtered ?? 100)) / 100);
          if (est !== null) rows = (rows ?? 0) + est;
          plans.push(`${target.select_type} ${target.table ?? ''} (${target.type ?? 'n/a'}${target.key ? ` using ${target.key}` : ''}) — est. ${est ?? '?'} rows`);
        }
        await query(c, 'ROLLBACK');
        return { rows, plan: plans.join('\n'), error: null };
      }, true);
    } catch (err) {
      return { rows: null, plan: null, error: (err as Error).message };
    }
  }

  async explain(text: string): Promise<string> {
    const { mariadb } = await this.serverContext();
    return this.withConn(async (c) => {
      await this.limitTime(c, this.db.statementTimeoutMs);
      await query(c, 'START TRANSACTION READ ONLY');
      const rows = await query<Record<string, unknown>[]>(c, mariadb ? `EXPLAIN ${text}` : `EXPLAIN FORMAT=TREE ${text}`);
      await query(c, 'ROLLBACK');
      if (!mariadb) return rows.map((r) => String(Object.values(r)[0])).join('\n');
      return rows
        .map((r) => `${r.id} ${r.select_type} ${r.table ?? ''} type=${r.type ?? ''} key=${r.key ?? ''} rows=${r.rows ?? ''} ${r.Extra ?? ''}`.trim())
        .join('\n');
    });
  }

  async listTables(schema?: string): Promise<TableInfo[]> {
    return this.withConn(async (c) => {
      const rows = await query<any[]>(
        c,
        `SELECT TABLE_SCHEMA AS s, TABLE_NAME AS n, TABLE_TYPE AS t, TABLE_ROWS AS r, TABLE_COMMENT AS cm
           FROM information_schema.TABLES WHERE TABLE_SCHEMA = COALESCE(?, DATABASE()) ORDER BY TABLE_NAME`,
        [schema ?? null],
      );
      return rows.map((r) => ({
        schema: r.s,
        name: r.n,
        kind: r.t === 'BASE TABLE' ? 'table' : r.t === 'VIEW' ? 'view' : String(r.t).toLowerCase(),
        estimatedRows: r.r === null ? null : Number(r.r),
        comment: r.cm || null,
      }));
    });
  }

  async describeTable(table: string, schema?: string): Promise<Record<string, unknown> | null> {
    let s = schema ?? null;
    let t = table;
    if (!s && table.includes('.')) [s, t] = [table.slice(0, table.indexOf('.')), table.slice(table.indexOf('.') + 1)];
    return this.withConn(async (c) => {
      const [rel] = await query<any[]>(
        c,
        'SELECT TABLE_SCHEMA AS s, TABLE_NAME AS n, TABLE_COMMENT AS cm FROM information_schema.TABLES WHERE TABLE_SCHEMA = COALESCE(?, DATABASE()) AND TABLE_NAME = ?',
        [s, t],
      );
      if (!rel) return null;
      const args = [rel.s, rel.n];
      const columns = await query<any[]>(
        c,
        `SELECT COLUMN_NAME AS name, COLUMN_TYPE AS type, IS_NULLABLE = 'YES' AS nullable, COLUMN_DEFAULT AS \`default\`,
                NULLIF(COLUMN_COMMENT, '') AS comment, NULLIF(EXTRA, '') AS extra
           FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION`,
        args,
      );
      const indexes = await query<any[]>(
        c,
        `SELECT INDEX_NAME AS name, INDEX_NAME = 'PRIMARY' AS \`primary\`, NON_UNIQUE = 0 AS \`unique\`,
                GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS columns
           FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
          GROUP BY INDEX_NAME, NON_UNIQUE ORDER BY INDEX_NAME = 'PRIMARY' DESC, INDEX_NAME`,
        args,
      );
      const fks = await query<any[]>(
        c,
        `SELECT CONSTRAINT_NAME AS name,
                CONCAT('(', GROUP_CONCAT(COLUMN_NAME ORDER BY ORDINAL_POSITION), ') REFERENCES ', REFERENCED_TABLE_NAME,
                       '(', GROUP_CONCAT(REFERENCED_COLUMN_NAME ORDER BY ORDINAL_POSITION), ')') AS definition
           FROM information_schema.KEY_COLUMN_USAGE
          WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND REFERENCED_TABLE_NAME IS NOT NULL
          GROUP BY CONSTRAINT_NAME, REFERENCED_TABLE_NAME ORDER BY CONSTRAINT_NAME`,
        args,
      );
      const bool = (v: unknown) => v === 1 || v === '1' || v === true;
      return {
        schema: rel.s,
        name: rel.n,
        comment: rel.cm || null,
        columns: columns.map((col) => ({ ...col, nullable: bool(col.nullable) })),
        indexes: indexes.map((i) => ({ ...i, primary: bool(i.primary), unique: bool(i.unique) })),
        foreignKeys: fks,
      };
    });
  }

  async test(): Promise<{ serverVersion: string; user: string; warnings: string[] }> {
    return this.withConn(async (c) => {
      const [info] = await query<{ v: string; u: string }[]>(c, 'SELECT VERSION() AS v, CURRENT_USER() AS u');
      const grants = (await query<Record<string, string>[]>(c, 'SHOW GRANTS')).map((r) => String(Object.values(r)[0]));
      const warnings: string[] = [];
      const mariadb = /mariadb/i.test(info.v);
      if (mariadb && this.db.engine === 'mysql') warnings.push('This server is MariaDB: choose MariaDB as the engine.');
      if (!mariadb && this.db.engine === 'mariadb') warnings.push('This server is MySQL, not MariaDB: choose MySQL as the engine.');
      for (const g of grants) {
        const m = /^GRANT (.+?) ON (\S+) TO/i.exec(g);
        if (!m) continue;
        const [, privs, on] = m;
        const global = on === '*.*';
        if (global && /ALL PRIVILEGES/i.test(privs)) {
          warnings.push(`"${info.u}" has ALL PRIVILEGES on *.* (effectively root): anything you allow can bypass all database permissions. Use a dedicated user.`);
          continue;
        }
        if (global) {
          const list = privs.split(',').map((p) => p.trim().toUpperCase()).filter((p) => p !== 'USAGE');
          if (list.includes('FILE')) warnings.push(`"${info.u}" has FILE: it can read and write files on the database server.`);
          const risky = list.filter((p) => ['SUPER', 'PROCESS', 'SHUTDOWN', 'CREATE USER', 'RELOAD', 'SYSTEM_USER', 'SET_USER_ID', 'SET_ANY_DEFINER', 'CONNECTION_ADMIN', 'SYSTEM_VARIABLES_ADMIN'].includes(p));
          if (risky.length) warnings.push(`"${info.u}" has global ${risky.join(', ')}.`);
          const data = list.filter((p) => !risky.includes(p) && p !== 'FILE');
          if (data.length) warnings.push(`"${info.u}" has ${data.length > 4 ? 'privileges' : data.join(', ')} on every database (*.*), not just "${this.db.database}".`);
        }
        if (/WITH GRANT OPTION/i.test(g)) warnings.push(`"${info.u}" can grant its privileges to others (WITH GRANT OPTION on ${on}).`);
      }
      return { serverVersion: info.v, user: info.u, warnings };
    });
  }

  async close() {
    const pool = this.pool;
    this.pool = null;
    await new Promise<void>((r) => (pool ? pool.end(() => r()) : r()));
  }
}
