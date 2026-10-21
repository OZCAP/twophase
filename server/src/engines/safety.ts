import type { Analysis, StatementAnalysis } from './types.js';

/** Includes SQL-level PREPARE bodies, which must be checked before reaching the server. */
export function allStatements(statements: StatementAnalysis[]): StatementAnalysis[] {
  return statements.flatMap((s) => [s, ...(s.prepared ? allStatements([s.prepared.analysis]) : [])]);
}

export function safetyError(analysis: Analysis): string | undefined {
  if (analysis.safetyError) return analysis.safetyError;
  for (const s of allStatements(analysis.statements)) {
    if (s.flags.includes('opaque_function') || s.command === 'CALL' || s.command === 'DO') {
      return 'Stored routines and unknown functions are not supported: their indirect effects cannot be checked against table policies';
    }
    if (/^(CREATE|ALTER) (?:MATERIALIZED )?(?:VIEW|FUNCTION|PROCEDURE|TRIGGER|RULE|POLICY|TYPE|CAST|OPERATOR)\b/.test(s.command)) {
      return 'Defining objects with indirect SQL effects is not supported through the proxy';
    }
  }
  return undefined;
}

export function referencedTables(analysis: Analysis): string[] {
  return [...new Set(allStatements(analysis.statements).flatMap((s) => s.accesses.flatMap((a) => a.table ? [a.table] : [])))];
}

/** Conservative across search paths: an unqualified name matching any view is refused. */
export function opaqueRelationError(analysis: Analysis, relations: { schema: string; name: string }[]): string | undefined {
  const opaque = new Set(relations.flatMap((r) => [r.name, `${r.schema}.${r.name}`]));
  const found = referencedTables(analysis).find((name) => opaque.has(name));
  return found ? `Views and foreign tables are not supported (${found}): their indirect effects cannot be checked against table policies` : undefined;
}

export function mysqlBatchError(statements: StatementAnalysis[]): string | undefined {
  if (statements.length > 1 && statements.some((s) => s.kind === 'ddl' || s.kind === 'admin' || s.command === 'TRUNCATE' || s.flags.includes('no_transaction'))) {
    return 'MySQL/MariaDB batches containing DDL, TRUNCATE or admin statements are not atomic; submit those statements separately';
  }
  return undefined;
}

/** PostgreSQL timeout literals: no expressions, zero (disabled), or unbounded values. */
export function timeoutMillis(value: string): number | null {
  const match = /^\s*(\d+(?:\.\d+)?)\s*(us|ms|s|min|h|d)?\s*$/i.exec(value);
  if (!match) return null;
  const units: Record<string, number> = { us: 0.001, ms: 1, s: 1000, min: 60000, h: 3600000, d: 86400000 };
  const ms = Number(match[1]) * units[(match[2] ?? 'ms').toLowerCase()];
  return Number.isFinite(ms) && ms >= 1 ? Math.floor(ms) : null;
}
