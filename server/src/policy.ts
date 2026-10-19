import type { Access, Analysis, Operation } from './engines/types.js';
import type { Action, DatabaseConfig, Grant, Rule } from './store.js';

const RESTRICTIVENESS: Record<Action, number> = { allow: 0, approve: 1, deny: 2 };

export function isGlob(pattern: string): boolean {
  return /[*?]/.test(pattern);
}

export function globMatch(pattern: string, value: string): boolean {
  if (!isGlob(pattern)) return pattern === value;
  const re = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${re}$`).test(value);
}

/**
 * Does a table pattern cover a table? A pattern matches either the full name as written in the
 * SQL (`app.orders`) or the bare table name (`orders`), so `orders` covers `public.orders` too.
 * A null pattern means "any table" and also covers statements that touch no table; a specific
 * pattern never covers those.
 */
export function tableMatches(pattern: string | null, table: string | null): boolean {
  if (pattern === null) return true;
  if (table === null) return false;
  const bare = table.includes('.') ? table.slice(table.lastIndexOf('.') + 1) : table;
  return globMatch(pattern, table) || globMatch(pattern, bare);
}

/**
 * Specificity: a client-specific rule beats an everyone rule; an exact table beats a glob beats
 * "any table". Ties go to the stricter action, so overlapping rules never open things up.
 */
function specificity(rule: Rule): number {
  const table = rule.tablePattern === null ? 0 : isGlob(rule.tablePattern) ? 1 : 2;
  return (rule.userId ? 4 : 0) + table;
}

export function defaultAction(db: Pick<DatabaseConfig, 'defaultRead' | 'defaultWrite' | 'defaultDdl' | 'defaultAdmin'>, op: Operation): Action {
  return { read: db.defaultRead, write: db.defaultWrite, ddl: db.defaultDdl, admin: db.defaultAdmin }[op];
}

export interface AccessDecision {
  access: Access;
  action: Action;
  /** The rule that decided, or null when the database's default for the operation applied. */
  rule: Rule | null;
}

/** Pass `userId: null` to see the everyone-baseline. */
export function decideAccess(rules: Rule[], db: DatabaseConfig, userId: string | null, access: Access): AccessDecision {
  const matching = rules.filter(
    (r) => r.operation === access.op && (r.userId === null || r.userId === userId) && tableMatches(r.tablePattern, access.table),
  );
  if (matching.length === 0) return { access, action: defaultAction(db, access.op), rule: null };
  matching.sort((a, b) => specificity(b) - specificity(a) || RESTRICTIVENESS[b.action] - RESTRICTIVENESS[a.action]);
  return { access, action: matching[0].action, rule: matching[0] };
}

export interface PolicyDecision {
  /** Strictest action across every access of every statement. */
  action: Action;
  decisions: AccessDecision[];
  /** The deciding rule for a deny (for audit / error messages). */
  denyRule: Rule | null;
}

export function evaluateAnalysis(rules: Rule[], db: DatabaseConfig, userId: string, analysis: Analysis): PolicyDecision {
  const decisions = analysis.statements.flatMap((s) => s.accesses.map((a) => decideAccess(rules, db, userId, a)));
  let action: Action = 'allow';
  for (const d of decisions) if (RESTRICTIVENESS[d.action] > RESTRICTIVENESS[action]) action = d.action;
  const denied = decisions.find((d) => d.action === 'deny');
  return { action, decisions, denyRule: denied?.rule ?? null };
}

/**
 * Can this client ever do anything but read? If not, its wire sessions are forced read-only.
 * Conservative: answers "no" only when every non-deny rule is overridden everywhere it applies.
 */
export function canOnlyRead(rules: Rule[], db: DatabaseConfig, userId: string): boolean {
  for (const op of ['write', 'ddl', 'admin'] as const) {
    const applicable = rules.filter((r) => r.operation === op && (r.userId === null || r.userId === userId));
    // The default only applies where no "any table" rule matches.
    if (!applicable.some((r) => r.tablePattern === null) && defaultAction(db, op) !== 'deny') return false;
    const denies = applicable.filter((r) => r.action === 'deny');
    for (const r of applicable) {
      if (r.action === 'deny') continue;
      // A deny at least as specific, covering every table this rule matches, always wins (ties go to deny).
      const overridden = denies.some((d) => specificity(d) >= specificity(r) && (d.tablePattern === null || d.tablePattern === r.tablePattern));
      if (!overridden) return false;
    }
  }
  return true;
}

export function grantCovers(grant: Grant, userId: string, access: Access): boolean {
  return (
    (grant.userId === null || grant.userId === userId) &&
    (grant.operation === null || grant.operation === access.op) &&
    tableMatches(grant.tablePattern, access.table)
  );
}

/** Do these trust windows cover every access that would otherwise need a human? */
export function grantsCover(grants: Grant[], userId: string, asked: Access[]): boolean {
  return asked.every((a) => grants.some((g) => grantCovers(g, userId, a)));
}
