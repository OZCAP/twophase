/**
 * Engine-neutral vocabulary. Policy, approvals and audit only ever see these types, so adding
 * another database engine means writing an analyzer/executor/wire frontend, nothing else.
 */

export const OPERATIONS = ['read', 'write', 'ddl', 'admin'] as const;
export type Operation = (typeof OPERATIONS)[number];

/** Ordering used to pick the "strictest" operation of a statement. */
export const OPERATION_RANK: Record<Operation, number> = { read: 0, write: 1, ddl: 2, admin: 3 };

/**
 * The specific kind of statement within each operation. Rules and trust windows can target an
 * operation (all writes) or a verb (only deletes).
 */
export const VERBS = {
  read: ['select'],
  write: ['insert', 'update', 'delete', 'merge', 'truncate', 'lock', 'function', 'call', 'notify', 'refresh'],
  ddl: ['create', 'alter', 'drop'],
  admin: ['admin'],
} as const satisfies Record<Operation, readonly string[]>;
export type Verb = (typeof VERBS)[Operation][number];
export const ALL_VERBS = Object.values(VERBS).flat() as Verb[];

/** What a rule or trust window can target: a whole operation, or one verb within it. */
export type PolicyTarget = Operation | Verb;
export const POLICY_TARGETS = [...new Set<PolicyTarget>([...OPERATIONS, ...ALL_VERBS])];

/** The operation a policy target belongs to (`delete` → `write`, `write` → `write`). */
export function targetOperation(target: PolicyTarget): Operation {
  if ((OPERATIONS as readonly string[]).includes(target)) return target as Operation;
  return OPERATIONS.find((op) => (VERBS[op] as readonly string[]).includes(target))!;
}

/**
 * One thing a statement does: an operation and the specific verb, on a table (`schema.table` or
 * bare `table`) or on nothing table-specific (null).
 */
export interface Access {
  op: Operation;
  verb: Verb;
  table: string | null;
}

export interface StatementAnalysis {
  /** The statement's own SQL text (a slice of the submitted string). */
  text: string;
  /** e.g. SELECT, UPDATE, CREATE TABLE, EXPLAIN ANALYZE, SET. */
  command: string;
  /** Strictest operation, or `session` for transaction control / harmless session settings (always allowed). */
  kind: Operation | 'session';
  accesses: Access[];
  /** Notable traits for reviewers and executors, e.g. `no_where`, `destructive`, `no_transaction`, `transaction_control`. */
  flags: string[];
  /** For PREPARE: the analysis of the prepared query, to reuse at EXECUTE. */
  prepared?: { name: string; analysis: StatementAnalysis };
}

export interface Analysis {
  statements: StatementAnalysis[];
  /** Parse error, if the SQL could not be parsed (the analysis then contains one `admin` statement). */
  error: string | null;
}

export interface TableInfo {
  schema: string;
  name: string;
  kind: string;
  estimatedRows: number | null;
  comment: string | null;
}

export interface Estimate {
  /** Planner's estimated rows for the top plan node (for DML: rows affected). */
  rows: number | null;
  plan: string | null;
  error: string | null;
}

export interface ColumnInfo {
  name: string;
  type: string;
}

export interface StatementResult {
  command: string;
  rowCount: number | null;
  columns: ColumnInfo[];
  rows: Record<string, unknown>[];
  truncated: boolean;
}

export class QueryError extends Error {
  constructor(
    message: string,
    /** SQLSTATE, when the database reported one. */
    readonly sqlstate: string | null,
    readonly detail?: string,
  ) {
    super(message);
  }
}

/**
 * The proxy's own connections to one database, used by the hosted MCP and the admin UI. Reads run
 * inside read-only transactions, so the database itself refuses any write the classifier missed.
 */
export interface Executor {
  /** How parameters are written in SQL passed to `run`: `$1` (Postgres) or `?` (MySQL). */
  readonly placeholder: '$1' | '?';
  /** Classify SQL as this database would run it (with its function catalog, quoting mode, …). */
  analyze(sql: string): Promise<Analysis>;
  /** Runs already-approved statements: read-only and rolled back, or as one committed transaction. */
  run(statements: StatementAnalysis[], opts: { readOnly: boolean; params?: unknown[]; maxRows: number }): Promise<StatementResult[]>;
  /** Planner estimate of rows a write would touch (plain EXPLAIN — nothing is executed). */
  estimate(statements: StatementAnalysis[], params?: unknown[]): Promise<Estimate>;
  explain(text: string): Promise<string>;
  listTables(schema?: string): Promise<TableInfo[]>;
  /** The name a listed table has in statement analyses (what rules match against). */
  tableName(t: TableInfo): string;
  describeTable(table: string, schema?: string): Promise<Record<string, unknown> | null>;
  /** Connectivity check plus warnings about an over-privileged proxy login. */
  test(): Promise<{ serverVersion: string; user: string; warnings: string[] }>;
  close(): Promise<void>;
}
