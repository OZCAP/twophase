import type { Access, PolicyTarget } from './engines/types.js';
import type { EventBus } from './events.js';
import { grantsCover } from './policy.js';
import type { PushService } from './push/index.js';
import type { Approval, ApprovalInput, ApprovalStatus, DatabaseConfig, Grant, ProxyUser, Store } from './store.js';

export type DecisionScope = 'once' | 'tables' | 'operation' | 'database';

export interface DecisionInput {
  decision: 'approve' | 'deny';
  /**
   * `once`: only this statement. Otherwise also open a trust window for this client:
   * `tables`: the same verb(s) on the same table(s), e.g. "delete on orders"; `operation`: those
   * verb(s) on any table of this database, e.g. "all deletes"; `database`: anything that would ask.
   */
  scope?: DecisionScope;
  /** Length of the trust window. null/undefined = until revoked. */
  durationMinutes?: number | null;
}

export class ApprovalError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

/** Trust windows needed to cover `asked` at the given scope. */
export function grantsForScope(scope: Exclude<DecisionScope, 'once'>, asked: Access[]): { operation: PolicyTarget | null; tablePattern: string | null }[] {
  const unique = <T>(items: T[], key: (t: T) => string) => [...new Map(items.map((i) => [key(i), i])).values()];
  // Older approvals stored no verb; fall back to the whole operation for those.
  const target = (a: Access): PolicyTarget => a.verb ?? a.op;
  if (scope === 'database') return [{ operation: null, tablePattern: null }];
  if (scope === 'operation') return unique(asked, target).map((a) => ({ operation: target(a), tablePattern: null }));
  return unique(asked, (a) => `${target(a)}:${a.table}`).map((a) => ({ operation: target(a), tablePattern: a.table }));
}

/**
 * Holds statements that need a human decision. A pending request is a promise parked in
 * `waiters`; it settles when the operator decides, the request times out, or the client gives up.
 */
export class ApprovalService {
  private waiters = new Map<string, { resolve: (a: Approval) => void; timer: NodeJS.Timeout }>();

  constructor(
    private store: Store,
    private events: EventBus,
    private push: PushService,
    private timeoutSeconds: number,
  ) {
    // Requests that were waiting when the process died can never be answered.
    store.expireStalePendingApprovals();
  }

  get timeoutMs() {
    return this.timeoutSeconds * 1000;
  }

  request(
    input: Omit<ApprovalInput, 'expiresAt'>,
    ctx: { db: DatabaseConfig; user: ProxyUser; signal?: AbortSignal; onCreated?: (a: Approval) => void },
  ): Promise<Approval> {
    const approval = this.store.createApproval({ ...input, expiresAt: new Date(Date.now() + this.timeoutMs) });

    const result = new Promise<Approval>((resolve) => {
      const timer = setTimeout(() => this.finish(approval.id, 'expired'), this.timeoutMs);
      this.waiters.set(approval.id, { resolve, timer });
      if (ctx.signal?.aborted) queueMicrotask(() => this.finish(approval.id, 'cancelled'));
      ctx.signal?.addEventListener('abort', () => this.finish(approval.id, 'cancelled'), { once: true });
    });

    ctx.onCreated?.(approval);
    this.events.emit('approval.created', approval);
    void this.push.notifyApproval(approval, ctx.db, ctx.user);
    return result;
  }

  decide(id: string, input: DecisionInput): Approval {
    const approval = this.store.getApproval(id);
    if (!approval) throw new ApprovalError('Approval not found', 404);
    if (approval.status !== 'pending') throw new ApprovalError(`Approval is already ${approval.status}`, 409);

    if (input.decision === 'deny') return this.finish(id, 'denied')!;
    const scope = input.scope ?? 'once';
    if (scope === 'once') return this.finish(id, 'approved')!;

    const expiresAt = input.durationMinutes ? new Date(Date.now() + input.durationMinutes * 60_000) : null;
    const created = grantsForScope(scope, approval.asked).map((g) =>
      this.store.createGrant({ ...g, databaseId: approval.databaseId, userId: approval.userId, expiresAt, approvalId: approval.id, note: null }),
    );
    for (const g of created) this.events.emit('grant.created', g);
    const decided = this.finish(id, 'approved', created[0]?.id ?? null)!;
    this.approveCovered(approval.databaseId);
    return decided;
  }

  createGrant(input: Omit<Grant, 'id' | 'createdAt' | 'approvalId'>): Grant {
    const grant = this.store.createGrant({ ...input, approvalId: null });
    this.events.emit('grant.created', grant);
    this.approveCovered(grant.databaseId);
    return grant;
  }

  revokeGrant(id: string): boolean {
    const ok = this.store.deleteGrant(id);
    if (ok) this.events.emit('grant.revoked', { id });
    return ok;
  }

  /** A new trust window also releases waiting requests it now covers. */
  private approveCovered(databaseId: string) {
    for (const id of [...this.waiters.keys()]) {
      const a = this.store.getApproval(id);
      if (!a || a.databaseId !== databaseId) continue;
      const grants = this.store.listActiveGrants({ databaseId, userId: a.userId });
      // The windows that were already trusted may have ended meanwhile: check everything again.
      if (grantsCover(grants, a.userId, [...a.asked, ...a.trusted])) this.finish(id, 'approved', grants[0]?.id ?? null);
    }
  }

  private finish(id: string, status: Exclude<ApprovalStatus, 'pending'>, grantId: string | null = null) {
    const updated = this.store.resolveApproval(id, status, grantId);
    if (!updated) return null;
    const waiter = this.waiters.get(id);
    if (waiter) {
      clearTimeout(waiter.timer);
      this.waiters.delete(id);
      waiter.resolve(updated);
    }
    this.events.emit('approval.resolved', updated);
    return updated;
  }

  shutdown() {
    for (const id of [...this.waiters.keys()]) this.finish(id, 'cancelled');
  }
}
