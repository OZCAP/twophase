import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { CallToolResult, ServerNotification, ServerRequest } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { Config } from '../config.js';
import { analyze } from '../engines/postgres/analyze.js';
import { QueryError, type ExecutorRegistry } from '../engines/postgres/executor.js';
import type { Analysis, StatementAnalysis } from '../engines/types.js';
import type { Gate, GateOutcome } from '../gate.js';
import { decideAccess } from '../policy.js';
import type { DatabaseConfig, ProxyUser, Store } from '../store.js';

export interface McpDeps {
  store: Store;
  gate: Gate;
  executors: ExecutorRegistry;
  config: Config;
}

const PROGRESS_INTERVAL_MS = 15_000;
const MAX_ROWS_LIMIT = 1000;

const fail = (text: string): CallToolResult => ({ content: [{ type: 'text', text }], isError: true });
const ok = (data: Record<string, unknown>): CallToolResult => ({
  content: [{ type: 'text', text: JSON.stringify(data) }],
  structuredContent: data,
});

/** Things a single stateless `query` call can't meaningfully do. */
function unsupportedOverMcp(s: StatementAnalysis): string | null {
  if (s.flags.includes('transaction_control')) return 'Transaction control is not available here: each query call already runs as one transaction.';
  if (s.flags.includes('session_setting')) return `${s.command}: use SET LOCAL, which applies to this call only.`;
  if (s.flags.includes('prepared_statement')) return 'PREPARE/EXECUTE/DEALLOCATE are not available here; pass parameters with `params` instead.';
  if (s.flags.includes('copy')) return 'COPY is not available over MCP. Use INSERT … SELECT or a regular SELECT.';
  if (s.flags.includes('listen') || s.flags.includes('session_reset')) return `${s.command} is not available over MCP.`;
  if (/^(DECLARE CURSOR|FETCH|MOVE|CLOSE)\b/.test(s.command)) return 'Cursors are not available over MCP; use LIMIT/OFFSET.';
  return null;
}

const synthetic = (command: string, table: string | null): Analysis => ({
  statements: [{ text: command, command, kind: 'read', accesses: [{ op: 'read', table }], flags: [] }],
  error: null,
});

/** The MCP server one client session talks to, for one database. */
export function createDatabaseMcpServer(databaseId: string, userId: string, deps: McpDeps): McpServer {
  const { store, gate, executors } = deps;
  const initial = store.getDatabase(databaseId)!;

  const server = new McpServer(
    { name: `twophase/${initial.slug}`, version: '0.2.0' },
    {
      instructions:
        `SQL access to the ${initial.engine} database "${initial.name}" through twophase. ` +
        'Reads run in read-only transactions. Writes, DDL and admin statements may be denied or may wait for a human to approve them; ' +
        'the call blocks until a decision. If a statement is denied, do not retry it in another form unless asked to.',
    },
  );

  // Re-read config on every call so disabling a client, database or access applies immediately.
  const current = (): { db: DatabaseConfig; user: ProxyUser } => {
    const db = store.getDatabase(databaseId);
    const user = store.getUser(userId);
    const access = user?.access.find((a) => a.databaseId === databaseId);
    if (!db?.enabled || !user?.enabled || !access?.allowMcp) throw new Error('Access to this database has been revoked');
    return { db, user };
  };

  type Extra = RequestHandlerExtra<ServerRequest, ServerNotification>;
  /** While waiting for a human, keep the client's request alive with progress notifications. */
  const keepalive = (extra: Extra) => {
    const token = extra._meta?.progressToken;
    let timer: NodeJS.Timeout | null = null;
    return {
      start: () => {
        if (token === undefined || timer) return;
        let tick = 0;
        timer = setInterval(() => {
          void extra
            .sendNotification({ method: 'notifications/progress', params: { progressToken: token, progress: ++tick, message: 'Waiting for human approval…' } })
            .catch(() => {});
        }, PROGRESS_INTERVAL_MS);
      },
      stop: () => timer && clearInterval(timer),
    };
  };

  const guarded = async (
    extra: Extra,
    req: { db: DatabaseConfig; user: ProxyUser; sql: string; analysis: Analysis; params?: unknown[]; estimate?: boolean },
    run: (outcome: Extract<GateOutcome, { allowed: true }>) => Promise<CallToolResult>,
  ): Promise<CallToolResult> => {
    const ka = keepalive(extra);
    const exec = executors.get(req.db);
    let outcome: GateOutcome;
    try {
      outcome = await gate.check({
        surface: 'mcp',
        db: req.db,
        user: req.user,
        sql: req.sql,
        params: req.params?.map((p) => (p === null || p === undefined ? null : String(p))) ?? null,
        analysis: req.analysis,
        signal: extra.signal,
        estimate: req.estimate ? () => exec.estimate(req.analysis.statements, req.params) : undefined,
        onWaiting: ka.start,
      });
    } finally {
      ka.stop();
    }
    if (!outcome.allowed) return fail(`${outcome.message}. Do not retry this statement unless asked to.`);
    try {
      return await run(outcome);
    } catch (err) {
      const e = err instanceof QueryError ? err : new QueryError(String((err as Error)?.message ?? err), null);
      outcome.finish({ error: e.message, sqlstate: e.sqlstate });
      return fail(`${e.sqlstate ? `[${e.sqlstate}] ` : ''}${e.message}${e.detail ? `\n${e.detail}` : ''}`);
    }
  };

  server.registerTool(
    'query',
    {
      title: 'Run SQL',
      description:
        'Run one or more SQL statements and return the rows. Multiple statements run in one transaction. ' +
        'Reads run read-only; writes/DDL may need human approval (the call waits). Use `params` ($1, $2, …) for values.',
      inputSchema: {
        sql: z.string().min(1).describe('SQL to run. Separate multiple statements with semicolons.'),
        params: z.array(z.union([z.string(), z.number(), z.boolean(), z.null()])).optional().describe('Values for $1, $2, … (single statement only).'),
        maxRows: z.number().int().min(1).max(MAX_ROWS_LIMIT).optional().describe('Maximum rows returned per statement.'),
      },
    },
    async ({ sql, params, maxRows }, extra) => {
      const { db, user } = current();
      const exec = executors.get(db);
      const analysis = analyze(sql, { catalog: await exec.functionCatalog() });
      if (analysis.statements.length === 0) return fail('The query is empty.');
      if (params?.length && analysis.statements.length > 1) return fail('`params` can only be used with a single statement.');
      const unsupported = analysis.statements.map(unsupportedOverMcp).find(Boolean);
      if (unsupported) return fail(unsupported);

      return guarded(extra, { db, user, sql, analysis, params, estimate: true }, async (outcome) => {
        const started = Date.now();
        const readOnly = analysis.statements.every((s) => s.kind === 'read' || s.kind === 'session');
        const statements = await exec.run(analysis.statements, { readOnly, params, maxRows: Math.min(maxRows ?? db.maxRows, MAX_ROWS_LIMIT) });
        outcome.finish({ rowCount: statements.reduce((n, s) => n + (s.rowCount ?? 0), 0) });
        return ok({ statements, durationMs: Date.now() - started });
      });
    },
  );

  server.registerTool(
    'list_tables',
    {
      title: 'List tables',
      description: 'List tables and views you can read, with estimated row counts and comments.',
      inputSchema: { schema: z.string().optional().describe('Only this schema (default: all non-system schemas).') },
      annotations: { readOnlyHint: true },
    },
    async ({ schema }, extra) => {
      const { db, user } = current();
      return guarded(extra, { db, user, sql: `-- list_tables(${schema ?? ''})`, analysis: synthetic('LIST TABLES', null) }, async (outcome) => {
        const rules = store.listRules({ databaseId: db.id });
        const visible = (await executors.get(db).listTables(schema)).filter(
          (t) => decideAccess(rules, db, user.id, { op: 'read', table: `${t.schema}.${t.name}` }).action !== 'deny',
        );
        outcome.finish({ rowCount: visible.length });
        return ok({ tables: visible });
      });
    },
  );

  server.registerTool(
    'describe_table',
    {
      title: 'Describe table',
      description: 'Columns (type, nullability, default), indexes, foreign keys and comments of a table or view.',
      inputSchema: {
        table: z.string().min(1).describe('Table name, optionally schema-qualified (app.orders).'),
        schema: z.string().optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ table, schema }, extra) => {
      const { db, user } = current();
      const name = schema ? `${schema}.${table}` : table;
      return guarded(extra, { db, user, sql: `-- describe_table(${name})`, analysis: synthetic('DESCRIBE TABLE', name) }, async (outcome) => {
        const info = await executors.get(db).describeTable(table, schema);
        outcome.finish({ rowCount: info ? 1 : 0 });
        return info ? ok(info) : fail(`Table "${name}" was not found.`);
      });
    },
  );

  server.registerTool(
    'explain',
    {
      title: 'Explain a query',
      description: 'Show the query plan for one statement without running it (plain EXPLAIN; ANALYZE is not allowed).',
      inputSchema: { sql: z.string().min(1).describe('A single statement to plan.') },
      annotations: { readOnlyHint: true },
    },
    async ({ sql }, extra) => {
      const { db, user } = current();
      const exec = executors.get(db);
      // Classify exactly what will run, so "ANALYZE …" smuggled into the input is caught.
      const analysis = analyze(`EXPLAIN ${sql}`, { catalog: await exec.functionCatalog() });
      if (analysis.statements.length !== 1) return fail('explain takes exactly one statement.');
      if (analysis.statements[0].flags.includes('explain_analyze')) return fail('EXPLAIN ANALYZE executes the statement; use the query tool for that.');
      return guarded(extra, { db, user, sql: `EXPLAIN ${sql}`, analysis }, async (outcome) => {
        const plan = await exec.explain(analysis.statements[0].text.replace(/^EXPLAIN\s+/i, ''));
        outcome.finish({});
        return ok({ plan });
      });
    },
  );

  return server;
}
