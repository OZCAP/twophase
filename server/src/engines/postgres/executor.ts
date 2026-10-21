import pg from 'pg';
import { databaseStream } from '../../databaseSocket.js';
import Cursor from 'pg-cursor';
import type { ConnectionOptions } from 'node:tls';
import type { DatabaseConfig } from '../../store.js';
import { capResultSize, jsonCell, uniqueNames } from '../results.js';
import { QueryError, type Analysis, type Estimate, type Executor, type StatementAnalysis, type StatementResult, type TableInfo } from '../types.js';
import { analyze, type AnalyzeContext } from './analyze.js';
import type { FunctionCatalog } from './functions.js';
import { allStatements, opaqueRelationError, referencedTables, safetyError, timeoutMillis } from '../safety.js';

export { QueryError };

const TYPE_NAMES: Record<number, string> = {
  16: 'bool', 17: 'bytea', 18: 'char', 19: 'name', 20: 'int8', 21: 'int2', 23: 'int4', 25: 'text', 26: 'oid',
  114: 'json', 700: 'float4', 701: 'float8', 1042: 'bpchar', 1043: 'varchar', 1082: 'date', 1083: 'time',
  1114: 'timestamp', 1184: 'timestamptz', 1186: 'interval', 1700: 'numeric', 2950: 'uuid', 3802: 'jsonb',
};

/** node-postgres TLS options for an sslmode (`prefer` is resolved by probing; see `ssl()`). */
export function tlsFor(db: Pick<DatabaseConfig, 'sslmode' | 'host'>): ConnectionOptions | false {
  if (db.sslmode === 'disable') return false;
  if (db.sslmode === 'verify-full') return { rejectUnauthorized: true, servername: db.host };
  return { rejectUnauthorized: false };
}

function toQueryError(err: unknown): QueryError {
  if (err instanceof QueryError) return err;
  const e = err as { message?: string; code?: string; detail?: string };
  return new QueryError(e.message ?? String(err), typeof e.code === 'string' && /^[0-9A-Z]{5}$/.test(e.code) ? e.code : null, e.detail);
}

/**
 * The proxy's own connections to one database: runs MCP queries, plans for estimates, catalog
 * lookups. Reads always run inside `BEGIN READ ONLY`, so Postgres itself refuses any write the
 * classifier might have missed.
 */
export class PostgresExecutor implements Executor {
  readonly placeholder = '$1';
  private pool: pg.Pool | null = null;
  private resolvedSsl: Promise<ConnectionOptions | false> | null = null;

  constructor(readonly db: DatabaseConfig) {}

  private ssl(): Promise<ConnectionOptions | false> {
    return (this.resolvedSsl ??= (async () => {
      const tls = tlsFor(this.db);
      if (this.db.sslmode !== 'prefer') return tls;
      // libpq's "prefer": use TLS if the server offers it, else plain.
      const probe = new pg.Client({ ...this.connParams(), ssl: tls });
      try {
        await probe.connect();
        return tls;
      } catch (err) {
        if (/does not support SSL/i.test(String((err as Error).message))) return false;
        throw err;
      } finally {
        await probe.end().catch(() => {});
      }
    })().catch((err) => {
      this.resolvedSsl = null;
      throw err;
    }));
  }

  private connParams() {
    return {
      host: this.db.host,
      port: this.db.port,
      stream: databaseStream(this.db.host, this.db.port),
      database: this.db.database,
      user: this.db.user,
      password: this.db.password,
      application_name: 'twophase',
      connectionTimeoutMillis: 10_000,
    };
  }

  private async getPool(): Promise<pg.Pool> {
    if (this.pool) return this.pool;
    const ssl = await this.ssl();
    this.pool ??= new pg.Pool({ ...this.connParams(), ssl, max: 5, idleTimeoutMillis: 60_000 });
    this.pool.on('error', () => {}); // idle-client errors surface on next use
    return this.pool;
  }

  private async withClient<T>(fn: (c: pg.PoolClient) => Promise<T>, discardAfter = false): Promise<T> {
    const client = await (await this.getPool()).connect();
    let broken = discardAfter;
    try {
      return await fn(client);
    } catch (err) {
      await client.query('ROLLBACK').catch(() => (broken = true));
      throw toQueryError(err);
    } finally {
      client.release(broken);
    }
  }

  /** Refresh on each analysis: a stale catalog could miss newly created shadow functions. */
  functionCatalog(): Promise<FunctionCatalog | null> {
    return this.withClient(async (c) => {
      const { rows } = await c.query<{ nspname: string; proname: string; volatile: boolean; opaque: boolean }>(
        `SELECT n.nspname, p.proname, bool_or(p.provolatile = 'v') AS volatile,
                bool_or(n.nspname <> 'pg_catalog' OR p.oid >= 16384) AS opaque
           FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace GROUP BY 1, 2`,
      );
      const map: FunctionCatalog = new Map();
      for (const r of rows) {
        const schema = r.nspname.toLowerCase();
        const name = r.proname.toLowerCase();
        const value = r.opaque ? 'opaque' : r.volatile;
        map.set(`${schema}.${name}`, map.get(`${schema}.${name}`) === 'opaque' ? 'opaque' : value);
        map.set(name, map.get(name) === 'opaque' || r.opaque ? 'opaque' : !!map.get(name) || r.volatile);
      }
      return map;
    }).catch(() => null);
  }

  async analyze(sql: string, ctx: Pick<AnalyzeContext, 'prepared'> = {}): Promise<Analysis> {
    const catalog = await this.functionCatalog();
    const analysis = analyze(sql, { ...ctx, catalog });
    if (!catalog) return { ...analysis, safetyError: 'Cannot verify the database function catalog' };
    return this.validate(analysis);
  }

  async validate(analysis: Analysis): Promise<Analysis> {
    let error = safetyError(analysis);
    for (const s of allStatements(analysis.statements)) {
      if (s.timeout !== undefined) {
        const timeout = s.timeout === null ? null : timeoutMillis(s.timeout);
        if (timeout === null || timeout > this.db.statementTimeoutMs) error ??= `statement_timeout must be positive and no greater than ${this.db.statementTimeoutMs} ms`;
      }
    }
    if (!error && referencedTables(analysis).length) {
      try {
        const relations = await this.withClient(async (c) => (await c.query<{ schema: string; name: string }>(
          `SELECT n.nspname AS schema, c.relname AS name FROM pg_class c
           JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('v','f')`,
        )).rows);
        error = opaqueRelationError(analysis, relations);
      } catch { error = 'Cannot verify database relation metadata'; }
    }
    return error ? { ...analysis, safetyError: error } : analysis;
  }

  tableName(t: TableInfo): string {
    return `${t.schema}.${t.name}`;
  }

  /**
   * Runs already-approved statements. `readOnly` wraps them in BEGIN READ ONLY … ROLLBACK;
   * otherwise BEGIN … COMMIT so a multi-statement call is atomic. A single statement that can't
   * run in a transaction block (CONCURRENTLY, VACUUM) runs on its own in autocommit.
   */
  async run(
    statements: StatementAnalysis[],
    opts: { readOnly: boolean; params?: unknown[]; maxRows: number },
  ): Promise<StatementResult[]> {
    const checked = await this.validate({ statements, error: null });
    if (checked.safetyError) throw new QueryError(checked.safetyError, '0A000');
    const timeout = Math.max(1, Math.round(this.db.statementTimeoutMs));
    const autocommit = statements.length === 1 && statements[0].flags.includes('no_transaction');
    // Anything but a plain read may leave session state behind (temp tables, …): don't reuse that connection.
    const discard = statements.some((s) => s.kind !== 'read');
    const results = await this.withClient(async (c) => {
      if (autocommit) {
        await c.query(`SET statement_timeout = ${timeout}`);
        return [await this.runOne(c, statements[0].text, opts.params, opts.maxRows)];
      }
      await c.query(opts.readOnly ? 'BEGIN READ ONLY' : 'BEGIN');
      await c.query(`SET LOCAL statement_timeout = ${timeout}`);
      const out: StatementResult[] = [];
      for (const s of statements) out.push(await this.runOne(c, s.text, opts.params, opts.maxRows));
      await c.query(opts.readOnly ? 'ROLLBACK' : 'COMMIT');
      return out;
    }, discard || autocommit);
    return capResultSize(results);
  }

  private async runOne(c: pg.PoolClient, text: string, params: unknown[] | undefined, maxRows: number): Promise<StatementResult> {
    const cursor = c.query(new Cursor(text, params, { rowMode: 'array' }));
    try {
      const rows = (await cursor.read(maxRows + 1)) as unknown[][];
      const result = (cursor as unknown as { _result: pg.QueryResult })._result;
      const fields = result?.fields ?? [];
      const names = uniqueNames(fields.map((f) => f.name));
      return {
        command: result?.command ?? '',
        rowCount: result?.rowCount ?? (fields.length ? Math.min(rows.length, maxRows) : null),
        columns: fields.map((f, i) => ({ name: names[i], type: TYPE_NAMES[f.dataTypeID] ?? String(f.dataTypeID) })),
        rows: rows.slice(0, maxRows).map((r) => Object.fromEntries(names.map((n, i) => [n, jsonCell(r[i])]))),
        truncated: rows.length > maxRows,
      };
    } finally {
      await cursor.close();
    }
  }

  /** Planner estimate for writes (plain EXPLAIN — never ANALYZE, nothing is executed). */
  async estimate(statements: StatementAnalysis[], params?: unknown[]): Promise<Estimate> {
    const writes = statements.filter((s) => s.kind === 'write');
    if (writes.length === 0) return { rows: null, plan: null, error: null };
    try {
      return await this.withClient(async (c) => {
        await c.query('BEGIN READ ONLY');
        await c.query('SET LOCAL statement_timeout = 2000');
        let rows = 0;
        const plans: string[] = [];
        for (const s of writes) {
          const { rows: out } = await c.query(`EXPLAIN (FORMAT JSON) ${s.text}`, writes.length === 1 ? params : undefined);
          const plan = (out[0]['QUERY PLAN'] as { Plan: Record<string, any> }[])[0].Plan;
          rows += affectedRows(plan);
          plans.push(summarizePlan(plan));
        }
        await c.query('ROLLBACK');
        return { rows, plan: plans.join('\n'), error: null };
      });
    } catch (err) {
      return { rows: null, plan: null, error: (err as Error).message };
    }
  }

  async explain(text: string): Promise<string> {
    const checked = await this.analyze(`EXPLAIN ${text}`);
    if (checked.safetyError) throw new QueryError(checked.safetyError, '0A000');
    return this.withClient(async (c) => {
      await c.query('BEGIN READ ONLY');
      await c.query(`SET LOCAL statement_timeout = ${this.db.statementTimeoutMs}`);
      const { rows } = await c.query(`EXPLAIN ${text}`);
      await c.query('ROLLBACK');
      return rows.map((r) => r['QUERY PLAN']).join('\n');
    });
  }

  async listTables(schema?: string): Promise<TableInfo[]> {
    return this.withClient(async (c) => {
      const { rows } = await c.query(
        `SELECT n.nspname AS schema, c.relname AS name,
                CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned table' WHEN 'v' THEN 'view'
                               WHEN 'm' THEN 'materialized view' WHEN 'f' THEN 'foreign table' END AS kind,
                NULLIF(c.reltuples, -1)::bigint AS estimated_rows, obj_description(c.oid, 'pg_class') AS comment
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
            AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
            AND ($1::text IS NULL OR n.nspname = $1)
          ORDER BY 1, 2`,
        [schema ?? null],
      );
      return rows.map((r) => ({ schema: r.schema, name: r.name, kind: r.kind, estimatedRows: r.estimated_rows === null ? null : Number(r.estimated_rows), comment: r.comment }));
    });
  }

  async describeTable(table: string, schema?: string): Promise<Record<string, unknown> | null> {
    let s = schema;
    let t = table;
    if (!s && table.includes('.')) [s, t] = [table.slice(0, table.indexOf('.')), table.slice(table.indexOf('.') + 1)];
    return this.withClient(async (c) => {
      const rel = await c.query(
        `SELECT c.oid, n.nspname, c.relname, obj_description(c.oid, 'pg_class') AS comment
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE c.oid = to_regclass(CASE WHEN $1::text IS NULL THEN format('%I', $2::text) ELSE format('%I.%I', $1::text, $2::text) END)`,
        [s ?? null, t],
      );
      if (!rel.rows[0]) return null;
      const oid = rel.rows[0].oid;
      const [cols, idx, fks] = await Promise.all([
        c.query(
          `SELECT a.attname AS name, format_type(a.atttypid, a.atttypmod) AS type, NOT a.attnotnull AS nullable,
                  pg_get_expr(d.adbin, d.adrelid) AS "default", col_description(a.attrelid, a.attnum) AS comment
             FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
            WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`,
          [oid],
        ),
        c.query(`SELECT i.relname AS name, x.indisprimary AS primary, x.indisunique AS unique, pg_get_indexdef(x.indexrelid) AS definition
                   FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid WHERE x.indrelid = $1 ORDER BY 2 DESC, 1`, [oid]),
        c.query(`SELECT conname AS name, pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid = $1 AND contype = 'f' ORDER BY 1`, [oid]),
      ]);
      return {
        schema: rel.rows[0].nspname,
        name: rel.rows[0].relname,
        comment: rel.rows[0].comment,
        columns: cols.rows,
        indexes: idx.rows,
        foreignKeys: fks.rows,
      };
    });
  }

  /** Connectivity check plus warnings about an over-privileged proxy login. */
  async test(): Promise<{ serverVersion: string; user: string; warnings: string[] }> {
    return this.withClient(async (c) => {
      const { rows } = await c.query(
        `SELECT current_setting('server_version') AS version, current_user AS "user", r.rolsuper, r.rolcreaterole, r.rolbypassrls,
                ARRAY(SELECT b.rolname::text FROM pg_auth_members m JOIN pg_roles b ON b.oid = m.roleid WHERE m.member = r.oid) AS member_of
           FROM pg_roles r WHERE r.rolname = current_user`,
      );
      const r = rows[0];
      const warnings: string[] = [];
      if (r.rolsuper) warnings.push(`"${r.user}" is a superuser: anything you allow can bypass all database permissions. Use a dedicated role.`);
      if (r.rolcreaterole) warnings.push(`"${r.user}" can create roles.`);
      if (r.rolbypassrls) warnings.push(`"${r.user}" bypasses row-level security.`);
      for (const role of ['pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program', 'pg_signal_backend']) {
        if ((r.member_of as string[]).includes(role)) warnings.push(`"${r.user}" is a member of ${role}.`);
      }
      return { serverVersion: r.version, user: r.user, warnings };
    });
  }

  async close() {
    const pool = this.pool;
    this.pool = null;
    await pool?.end().catch(() => {});
  }
}

/** ModifyTable reports 0 rows unless RETURNING; the rows it will touch are its input's estimate. */
function affectedRows(plan: Record<string, any>): number {
  const node = plan['Node Type'] === 'ModifyTable' && plan.Plans?.[0] ? plan.Plans[0] : plan;
  return Number(node['Plan Rows'] ?? 0);
}

function summarizePlan(plan: Record<string, any>): string {
  const node = plan['Node Type'] + (plan.Operation ? ` (${plan.Operation})` : '');
  const target = plan['Relation Name'] ? ` on ${plan['Relation Name']}` : '';
  const child = plan.Plans?.[0];
  const via = child ? ` ← ${child['Node Type']}${child['Relation Name'] ? ` on ${child['Relation Name']}` : ''}${child['Index Name'] ? ` using ${child['Index Name']}` : ''}` : '';
  return `${node}${target}${via} — est. ${affectedRows(plan)} rows`;
}
