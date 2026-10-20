import { useEffect, useState } from 'react';
import { ENGINE_LABEL, previewSql, type Approval, type DecisionScope, type Grant, type PolicyTarget } from '../api';
import { useProxy } from '../state';
import { attempt, clock, Code, countdownClass, describeAccess, Empty, OpChip, relative, targetLabel, TRUST_DURATIONS, useNow } from '../ui';

export function ApprovalsView({ focusId }: { focusId?: string }) {
  const { api, pending, recent, grants } = useProxy();
  const focusedPending = focusId ? pending.find((a) => a.id === focusId) : undefined;
  // A linked approval that isn't waiting (any more): load it to say what became of it.
  const [linked, setLinked] = useState<Approval | 'missing' | null>(null);

  useEffect(() => {
    setLinked(null);
    if (!focusId || focusedPending) return;
    let cancelled = false;
    const local = recent.find((a) => a.id === focusId);
    if (local) setLinked(local);
    else api.approval(focusId).then((a) => !cancelled && setLinked(a), () => !cancelled && setLinked('missing'));
    return () => {
      cancelled = true;
    };
  }, [api, focusId, focusedPending, recent]);

  useEffect(() => {
    if (focusId) window.scrollTo({ top: 0 });
  }, [focusId]);

  const others = pending.filter((a) => a.id !== focusId);
  return (
    <div className="stack">
      {focusId && !focusedPending && linked && (
        <section>
          {linked === 'missing' ? (
            <article className="card focused">
              <h3>Approval not found</h3>
              <p className="muted">It may have been removed with its database.</p>
            </article>
          ) : linked.status === 'pending' ? null : (
            <ResolvedCard approval={linked} />
          )}
        </section>
      )}
      <section>
        <h2>Waiting for you</h2>
        {pending.length === 0 ? (
          <Empty title="Nothing to approve">Statements that need your approval show up here instantly.</Empty>
        ) : (
          <>
            {focusedPending && <PendingCard key={focusedPending.id} approval={focusedPending} focused />}
            {others.map((a) => (
              <PendingCard key={a.id} approval={a} focused={false} />
            ))}
          </>
        )}
      </section>

      <section>
        <h2>Trust windows</h2>
        {grants.length === 0 ? (
          <p className="muted">No active trust windows. Approving “and trust for …” opens one.</p>
        ) : (
          <ul className="list">
            {grants.map((g) => (
              <GrantRow key={g.id} grant={g} />
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>Recent decisions</h2>
        {recent.length === 0 ? (
          <p className="muted">No decisions yet.</p>
        ) : (
          <ul className="list">
            {recent.slice(0, 25).map((a) => (
              <li key={a.id} className="row event">
                <span className={`pill pill-${a.status}`}>{a.status}</span>
                <div className="grow">
                  <div>
                    {(a.verbs?.length ? a.verbs : a.operations).map((op) => (
                      <OpChip key={op} op={op} />
                    ))}{' '}
                    <span className="muted">
                      {a.userName} → {a.databaseName}
                    </span>
                  </div>
                  <div className="muted mono ellipsis">{previewSql(a.sql)}</div>
                </div>
                <span className="muted small">{relative(a.decidedAt ?? a.createdAt)}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

const STATUS_TEXT: Record<Approval['status'], string> = {
  pending: 'Waiting',
  approved: 'Approved',
  denied: 'Denied',
  expired: 'Expired: nobody decided in time, so it failed',
  cancelled: 'Withdrawn by the client before a decision',
};

/** The approval a notification pointed to, after it was decided. */
function ResolvedCard({ approval: a }: { approval: Approval }) {
  const now = useNow();
  return (
    <article id={`approval-${a.id}`} className="card focused">
      <header className="row">
        <div className="grow">
          <h3>
            <span className={`pill pill-${a.status}`}>{a.status}</span>{' '}
            {(a.verbs?.length ? a.verbs : a.operations).map((op) => (
              <OpChip key={op} op={op} />
            ))}{' '}
            <span className="mono">{a.tables.join(', ')}</span>
          </h3>
          <div className="muted">
            {STATUS_TEXT[a.status]} · {relative(a.decidedAt ?? a.createdAt, now)} · {a.userName} → {a.databaseName}
          </div>
        </div>
      </header>
      <Code>{a.sql}</Code>
    </article>
  );
}

function warningsFor(a: Approval): { text: string; danger?: boolean }[] {
  const flags = new Set(a.statements.flatMap((s) => s.flags));
  const out: { text: string; danger?: boolean }[] = [];
  if (flags.has('no_where')) out.push({ text: 'UPDATE/DELETE without WHERE — affects every row', danger: true });
  if (flags.has('destructive')) out.push({ text: 'Destructive: TRUNCATE or DROP', danger: true });
  if (flags.has('explain_analyze')) out.push({ text: 'EXPLAIN ANALYZE executes the statement for real' });
  if (a.statements.length > 1) out.push({ text: `${a.statements.length} statements, run together` });
  if (a.session?.transactionStatus === 'transaction') {
    const age = a.session.transactionAgeMs ? ` for ${Math.round(a.session.transactionAgeMs / 1000)}s` : '';
    out.push({ text: `Inside an open transaction${age}: its locks are held while you decide` });
  }
  return out;
}

function PendingCard({ approval: a, focused }: { approval: Approval; focused: boolean }) {
  const { decide, databases, grants } = useProxy();
  const now = useNow();
  const [busy, setBusy] = useState(false);
  const [minutes, setMinutes] = useState<number | null>(10);
  const remaining = Math.max(0, Math.round((new Date(a.expiresAt).getTime() - now) / 1000));
  // What's being asked, as specifically as we know it: DELETE rather than write.
  const askedTargets = [...new Set(a.asked.map((x): PolicyTarget => x.verb ?? x.op))];
  const warnings = warningsFor(a);
  const engine = databases.find((d) => d.id === a.databaseId)?.engine;
  const via = a.surface === 'wire' ? `${engine ? ENGINE_LABEL[engine] : 'SQL client'}${a.session?.applicationName ? ` (${a.session.applicationName})` : ''}` : 'MCP';

  const act = (d: Parameters<typeof decide>[1]) => {
    setBusy(true);
    void attempt(() => decide(a.id, d)).finally(() => setBusy(false));
  };
  const trust = (scope: DecisionScope) => act({ decision: 'approve', scope, durationMinutes: minutes });

  return (
    <article id={`approval-${a.id}`} className={`card pending ${focused ? 'focused' : ''}`}>
      <header className="row">
        <div className="grow">
          <h3>
            {askedTargets.map((op) => (
              <OpChip key={op} op={op} />
            ))}{' '}
            <span className="mono">{a.asked.map((x) => x.table).filter(Boolean).join(', ') || a.statements.map((s) => s.command).join(', ')}</span>
          </h3>
          <div className="muted">
            <strong>{a.userName}</strong> via {via} → {a.databaseName} · {relative(a.createdAt, now)}
          </div>
        </div>
        <span className={countdownClass(remaining)}>
          {clock(remaining)}
        </span>
      </header>

      {warnings.length > 0 && (
        <ul className="warnings">
          {warnings.map((w) => (
            <li key={w.text} className={w.danger ? 'danger' : ''}>
              ⚠ {w.text}
            </li>
          ))}
        </ul>
      )}

      <Code>{a.sql}</Code>
      {a.params && a.params.length > 0 && (
        <div className="small">
          <span className="muted">Parameters: </span>
          {a.params.map((p, i) => (
            <span key={i} className="mono">
              ${i + 1} = {p === null ? 'NULL' : JSON.stringify(p)}
              {i < a.params!.length - 1 ? ', ' : ''}
            </span>
          ))}
        </div>
      )}
      <dl className="kv">
        <dt>Needs approval</dt>
        <dd>{a.asked.map(describeAccess).join(', ')}</dd>
        {a.trusted && a.trusted.length > 0 && (
          <>
            <dt>Already trusted</dt>
            <dd>
              <ul className="trusted">
                {a.trusted.map((t) => {
                  const g = grants.find((x) => x.id === t.grantId);
                  const left = g?.expiresAt ? (new Date(g.expiresAt).getTime() - now) / 1000 : null;
                  return (
                    <li key={`${t.verb}:${t.table}`}>
                      {describeAccess(t)}{' '}
                      <span className="muted small">
                        {!g ? (
                          '· window ended, approving covers it'
                        ) : left === null ? (
                          '· window until revoked'
                        ) : (
                          <>
                            · window <span className={countdownClass(left)}>{clock(left)}</span> left
                          </>
                        )}
                      </span>
                    </li>
                  );
                })}
              </ul>
            </dd>
          </>
        )}
        {a.estimate && (
          <>
            <dt>Planner estimate</dt>
            <dd>
              {a.estimate.rows !== null ? (
                <>
                  ~{a.estimate.rows.toLocaleString()} row{a.estimate.rows === 1 ? '' : 's'}
                  {a.estimate.plan && <div className="muted small mono">{a.estimate.plan}</div>}
                </>
              ) : (
                <span className="muted">unavailable{a.estimate.error ? ` (${a.estimate.error})` : ''}</span>
              )}
            </dd>
          </>
        )}
      </dl>

      <div className="actions">
        <button className="btn approve" disabled={busy} onClick={() => act({ decision: 'approve' })}>
          Approve once
        </button>
        <div className="trust">
          <span className="muted small">and trust</span>
          <select value={minutes ?? ''} onChange={(e) => setMinutes(e.target.value ? Number(e.target.value) : null)}>
            {TRUST_DURATIONS.map((d) => (
              <option key={d.label} value={d.minutes ?? ''}>
                {d.label}
              </option>
            ))}
          </select>
          <button className="btn" disabled={busy} onClick={() => trust('tables')} title="The same operation(s) on the same table(s)">
            {a.asked.map(describeAccess).join(', ')}
          </button>
          <button className="btn" disabled={busy} onClick={() => trust('operation')} title="The same kind of statement on any table of this database">
            any {askedTargets.map(targetLabel).join(' + ')}
          </button>
          <button className="btn" disabled={busy} onClick={() => trust('database')} title="Anything that would ask on this database">
            everything on {a.databaseName}
          </button>
        </div>
        <button className="btn deny" disabled={busy} onClick={() => act({ decision: 'deny' })}>
          Deny
        </button>
      </div>
    </article>
  );
}

export function GrantRow({ grant: g }: { grant: Grant }) {
  const { api } = useProxy();
  const now = useNow();
  const what = g.operation ? targetLabel(g.operation) : 'anything that asks';
  const remaining = g.expiresAt ? (new Date(g.expiresAt).getTime() - now) / 1000 : null;
  return (
    <li className="row">
      <div className="grow">
        <div>
          <strong>{g.userName ?? 'Everyone'}</strong> may {what} on <span className="mono">{g.tablePattern ?? 'any table'}</span> in {g.databaseName}
        </div>
        <div className="muted small">
          {remaining === null ? (
            'until revoked'
          ) : (
            <>
              <span className={countdownClass(remaining)}>{clock(remaining)}</span> left
            </>
          )}
        </div>
      </div>
      <button className="btn small deny" onClick={() => attempt(() => api.revokeGrant(g.id))}>
        Revoke
      </button>
    </li>
  );
}
