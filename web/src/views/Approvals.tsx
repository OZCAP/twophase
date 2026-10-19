import { useEffect, useState } from 'react';
import { previewSql, type Approval, type DecisionScope, type Grant, type Operation } from '../api';
import { useProxy } from '../state';
import { attempt, Code, describeAccess, Empty, OP_LABEL, OpChip, relative, TRUST_DURATIONS, useNow } from '../ui';

export function ApprovalsView({ focusId }: { focusId?: string }) {
  const { pending, recent, grants } = useProxy();

  useEffect(() => {
    if (focusId) document.getElementById(`approval-${focusId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }, [focusId, pending.length]);

  return (
    <div className="stack">
      <section>
        <h2>Waiting for you</h2>
        {pending.length === 0 ? (
          <Empty title="Nothing to approve">Statements that need your approval show up here instantly.</Empty>
        ) : (
          pending.map((a) => <PendingCard key={a.id} approval={a} focused={a.id === focusId} />)
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
                    {a.operations.map((op) => (
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
  const { decide } = useProxy();
  const now = useNow();
  const [busy, setBusy] = useState(false);
  const [minutes, setMinutes] = useState<number | null>(10);
  const remaining = Math.max(0, Math.round((new Date(a.expiresAt).getTime() - now) / 1000));
  const askedOps = [...new Set(a.asked.map((x) => x.op))] as Operation[];
  const warnings = warningsFor(a);
  const via = a.surface === 'wire' ? `Postgres${a.session?.applicationName ? ` (${a.session.applicationName})` : ''}` : 'MCP';

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
            {askedOps.map((op) => (
              <OpChip key={op} op={op} />
            ))}{' '}
            <span className="mono">{a.asked.map((x) => x.table).filter(Boolean).join(', ') || a.statements.map((s) => s.command).join(', ')}</span>
          </h3>
          <div className="muted">
            <strong>{a.userName}</strong> via {via} → {a.databaseName} · {relative(a.createdAt, now)}
          </div>
        </div>
        <span className={`countdown ${remaining < 30 ? 'urgent' : ''}`}>
          {Math.floor(remaining / 60)}:{String(remaining % 60).padStart(2, '0')}
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
          <button className="btn" disabled={busy} onClick={() => trust('operation')} title="These operations on any table of this database">
            all {askedOps.map((op) => OP_LABEL[op]).join(' + ')}
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
  const now = useNow(15_000);
  const what = g.operation ? OP_LABEL[g.operation] : 'anything that asks';
  return (
    <li className="row">
      <div className="grow">
        <div>
          <strong>{g.userName ?? 'Everyone'}</strong> may {what} on <span className="mono">{g.tablePattern ?? 'any table'}</span> in {g.databaseName}
        </div>
        <div className="muted small">{g.expiresAt ? `expires ${relative(g.expiresAt, now)}` : 'until revoked'}</div>
      </div>
      <button className="btn small deny" onClick={() => attempt(() => api.revokeGrant(g.id))}>
        Revoke
      </button>
    </li>
  );
}
