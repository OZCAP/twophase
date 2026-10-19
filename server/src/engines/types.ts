/**
 * Engine-neutral vocabulary. Policy, approvals and audit only ever see these types, so adding
 * another database engine means writing an analyzer/executor/wire frontend, nothing else.
 */

export const OPERATIONS = ['read', 'write', 'ddl', 'admin'] as const;
export type Operation = (typeof OPERATIONS)[number];

/** Ordering used to pick the "strictest" operation of a statement. */
export const OPERATION_RANK: Record<Operation, number> = { read: 0, write: 1, ddl: 2, admin: 3 };

/** One thing a statement does: an operation, on a table (`schema.table` or bare `table`) or on nothing table-specific (null). */
export interface Access {
  op: Operation;
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
