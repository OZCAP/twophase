import type { ApprovalService } from './approvals.js';
import { ALL_VERBS, OPERATION_RANK, type Access, type Analysis, type Estimate, type Operation, type Verb } from './engines/types.js';
import type { EventBus } from './events.js';
import { evaluateAnalysis, grantCovers, grantsCover } from './policy.js';
import type { SessionInfo, TrustedAccess } from './db/schema.js';
import type { Approval, AuditDecision, DatabaseConfig, ProxyUser, Store, Surface } from './store.js';

export interface GateRequest {
  surface: Surface;
  db: DatabaseConfig;
  user: ProxyUser;
  sql: string;
  params?: (string | null)[] | null;
  analysis: Analysis;
  session?: SessionInfo;
  /** Aborting (client disconnected / cancelled) cancels a pending approval. */
  signal?: AbortSignal;
  /** Called only when a human is asked, to show the planner's row estimate on the card. */
  estimate?: () => Promise<Estimate | null>;
  /** Called once an approval is created (e.g. to tell a psql user it is waiting). */
  onWaiting?: (approval: Approval) => void;
}

export interface ExecResult {
  rowCount?: number | null;
  sqlstate?: string | null;
  error?: string | null;
}

export type GateOutcome =
  | {
      allowed: true;
      decision: Extract<AuditDecision, 'allowed' | 'granted' | 'approved'>;
      approvalId: string | null;
      /** Record how execution went. Call exactly once. */
      finish(result: ExecResult): void;
    }
  | {
      allowed: false;
      decision: Extract<AuditDecision, 'denied' | 'rejected' | 'expired' | 'cancelled'>;
      approvalId: string | null;
      /** Human-readable reason, suitable for an error message to the client. */
      message: string;
      /** SQLSTATE to report: 42501 insufficient_privilege, or 57014 query_canceled. */
      sqlstate: string;
    };

export function operationsOf(analysis: Analysis): Operation[] {
  const ops = new Set<Operation>();
  for (const s of analysis.statements) if (s.kind !== 'session') ops.add(s.kind);
  return [...ops].sort((a, b) => OPERATION_RANK[a] - OPERATION_RANK[b]);
}

/** Distinct verbs across all accesses, in a stable order (INSERT before DELETE, etc.). */
export function verbsOf(accesses: Access[]): Verb[] {
  const seen = new Set(accesses.map((a) => a.verb));
  return ALL_VERBS.filter((v) => seen.has(v));
}

export function tablesOf(accesses: Access[]): string[] {
  return [...new Set(accesses.map((a) => a.table).filter((t): t is string => !!t))].sort();
}

/** "delete on orders", "read on secrets", "admin". Reads stay "read": "select on x" says nothing more. */
const describeAccess = (a: Access) => `${a.op === 'read' || a.verb === a.op ? a.op : a.verb}${a.table ? ` on ${a.table}` : ''}`;

/**
 * Every statement, from every surface, goes through here: policy → trust windows → human approval,
 * with one audit row per decision. Statements that are only transaction control / harmless
 * session settings pass straight through and are not audited.
 */
export class Gate {
  constructor(
    private store: Store,
    private approvals: ApprovalService,
    private events: EventBus,
  ) {}

  /** What `check` would do, without asking anyone or writing audit rows. */
  preview(db: DatabaseConfig, user: ProxyUser, analysis: Analysis): 'allow' | 'ask' | 'deny' {
    if (operationsOf(analysis).length === 0) return 'allow';
    const policy = evaluateAnalysis(this.store.listRules({ databaseId: db.id }), db, user.id, analysis);
    if (policy.action !== 'approve') return policy.action;
    const asked = policy.decisions.filter((d) => d.action === 'approve').map((d) => d.access);
    return grantsCover(this.store.listActiveGrants({ databaseId: db.id, userId: user.id }), user.id, asked) ? 'allow' : 'ask';
  }

  async check(req: GateRequest): Promise<GateOutcome> {
    const { db, user, analysis } = req;
    const operations = operationsOf(analysis);
    const accesses = analysis.statements.flatMap((s) => s.accesses);
    const tables = tablesOf(accesses);
    const verbs = verbsOf(accesses);

    if (operations.length === 0) {
      return { allowed: true, decision: 'allowed', approvalId: null, finish: () => {} };
    }

    const audit = (decision: AuditDecision, extra: { ruleId?: string | null; approvalId?: string | null } & ExecResult & { durationMs?: number | null }) => {
      const entry = this.store.addAudit({
        databaseId: db.id,
        userId: user.id,
        surface: req.surface,
        sql: req.sql,
        operations,
        verbs,
        tables,
        decision,
        ruleId: extra.ruleId ?? null,
        approvalId: extra.approvalId ?? null,
        rowCount: extra.rowCount ?? null,
        sqlstate: extra.sqlstate ?? null,
        error: extra.error ?? null,
        durationMs: extra.durationMs ?? null,
      });
      this.events.emit('audit', entry);
    };
    const allowed = (decision: 'allowed' | 'granted' | 'approved', approvalId: string | null, ruleId: string | null): GateOutcome => {
      const started = Date.now();
      let done = false;
      return {
        allowed: true,
        decision,
        approvalId,
        finish: (r) => {
          if (done) return;
          done = true;
          audit(decision, { ...r, ruleId, approvalId, durationMs: Date.now() - started });
        },
      };
    };

    const rules = this.store.listRules({ databaseId: db.id });
    const policy = evaluateAnalysis(rules, db, user.id, analysis);

    if (policy.action === 'deny') {
      const denied = policy.decisions.find((d) => d.action === 'deny')!;
      audit('denied', { ruleId: policy.denyRule?.id ?? null, sqlstate: '42501' });
      const why = analysis.error ? `could not be parsed (${analysis.error})` : `${describeAccess(denied.access)} is not permitted`;
      const note = policy.denyRule?.note ? ` (${policy.denyRule.note})` : '';
      return { allowed: false, decision: 'denied', approvalId: null, sqlstate: '42501', message: `twophase: ${why} for ${user.name}${note}` };
    }

    const decidingRule = policy.decisions.find((d) => d.rule)?.rule ?? null;
    if (policy.action === 'allow') return allowed('allowed', null, decidingRule?.id ?? null);

    // Ask only about what no trust window covers yet; the rest is shown as already trusted.
    const grants = this.store.listActiveGrants({ databaseId: db.id, userId: user.id });
    const asked: Access[] = [];
    const trusted: TrustedAccess[] = [];
    for (const { action, access } of policy.decisions) {
      if (action !== 'approve') continue;
      const grant = grants.find((g) => grantCovers(g, user.id, access));
      if (grant) trusted.push({ ...access, grantId: grant.id });
      else asked.push(access);
    }
    if (asked.length === 0) return allowed('granted', null, null);

    const estimate = req.estimate && asked.some((a) => a.op === 'write') ? await req.estimate().catch(() => null) : null;
    const approval = await this.approvals.request(
      {
        databaseId: db.id,
        userId: user.id,
        surface: req.surface,
        sql: req.sql,
        params: req.params ?? null,
        statements: analysis.statements,
        asked: dedupeAccesses(asked),
        trusted: dedupeAccesses(trusted),
        operations,
        verbs: verbsOf(asked),
        tables,
        estimate,
        session: req.session ?? null,
      },
      { db, user, signal: req.signal, onCreated: req.onWaiting },
    );

    if (approval.status === 'approved') return allowed('approved', approval.id, null);
    const status = approval.status as 'denied' | 'expired' | 'cancelled';
    const decision = status === 'denied' ? 'rejected' : status;
    const sqlstate = status === 'denied' ? '42501' : '57014';
    audit(decision, { approvalId: approval.id, sqlstate });
    const message = {
      denied: 'twophase: denied by the operator',
      expired: `twophase: not approved within ${Math.round(this.approvals.timeoutMs / 1000)}s`,
      cancelled: 'twophase: canceling statement due to user request',
    }[status];
    return { allowed: false, decision, approvalId: approval.id, sqlstate, message };
  }
}

function dedupeAccesses<T extends Access>(accesses: T[]): T[] {
  return [...new Map(accesses.map((a) => [`${a.op}:${a.verb}:${a.table ?? ''}`, a])).values()];
}
