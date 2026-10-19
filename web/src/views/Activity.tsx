import { useState } from 'react';
import { previewSql, type AuditEntry } from '../api';
import { useProxy } from '../state';
import { attempt, Code, Empty, OpChip, relative, useNow } from '../ui';

const DECISION_LABEL: Record<AuditEntry['decision'], string> = {
  allowed: 'allowed by rule',
  granted: 'trust window',
  approved: 'approved',
  denied: 'blocked by rule',
  rejected: 'denied by you',
  expired: 'timed out',
  cancelled: 'cancelled',
};

export function ActivityView() {
  const { activity, loadMoreActivity } = useProxy();
  const [open, setOpen] = useState<number | null>(null);
  const now = useNow(30_000);

  return (
    <div className="stack">
      <h2>Activity</h2>
      {activity.length === 0 ? (
        <Empty title="No statements yet">Every statement through the proxy is logged here with its decision.</Empty>
      ) : (
        <ul className="list">
          {activity.map((e) => (
            <li key={e.id} className="clickable" onClick={() => setOpen(open === e.id ? null : e.id)}>
              <div className="row event">
                <span className={`pill pill-${e.decision}`}>{DECISION_LABEL[e.decision]}</span>
                <div className="grow">
                  <div>
                    {e.operations.map((op) => (
                      <OpChip key={op} op={op} />
                    ))}{' '}
                    <span className="surface">{e.surface === 'wire' ? 'PG' : 'MCP'}</span>{' '}
                    <span className="muted">
                      {e.userName} → {e.databaseName}
                    </span>
                    {e.error && <span className="pill pill-denied">{e.sqlstate ?? 'error'}</span>}
                  </div>
                  <div className="muted small mono ellipsis">{previewSql(e.sql)}</div>
                </div>
                <span className="muted small">
                  {relative(e.ts, now)}
                  {e.rowCount !== null && ` · ${e.rowCount} row${e.rowCount === 1 ? '' : 's'}`}
                  {e.durationMs !== null && ` · ${e.durationMs} ms`}
                </span>
              </div>
              {open === e.id && (
                <div onClick={(ev) => ev.stopPropagation()}>
                  <Code>{e.sql}</Code>
                  {e.tables.length > 0 && <p className="muted small">Tables: {e.tables.join(', ')}</p>}
                  {e.error && (
                    <p className="error">
                      {e.sqlstate ? `[${e.sqlstate}] ` : ''}
                      {e.error}
                    </p>
                  )}
                  <p className="muted small">{new Date(e.ts).toLocaleString()}</p>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {activity.length >= 50 && (
        <button className="btn" onClick={() => attempt(loadMoreActivity)}>
          Load more
        </button>
      )}
    </div>
  );
}
