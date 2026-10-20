import { useEffect, useState, type ReactNode } from 'react';
import { isMysql, targetOperation, VERBS, type Access, type Action, type Engine, type Operation, type PolicyTarget, type Verb } from './api';

export const ACTION_LABEL: Record<Action, string> = { allow: 'Allow', approve: 'Ask', deny: 'Deny' };

export const TRUST_DURATIONS: { label: string; minutes: number | null }[] = [
  { label: '10 min', minutes: 10 },
  { label: '30 min', minutes: 30 },
  { label: '1 hour', minutes: 60 },
  { label: '8 hours', minutes: 480 },
  { label: 'Until revoked', minutes: null },
];

export const OP_LABEL: Record<Operation, string> = { read: 'read', write: 'write', ddl: 'DDL', admin: 'admin' };
export const OP_DESCRIPTION: Record<Operation, string> = {
  read: 'SELECT, SHOW, plain EXPLAIN, COPY TO',
  write: 'INSERT, UPDATE, DELETE, MERGE, TRUNCATE, COPY FROM, row locks, side-effecting functions',
  ddl: 'CREATE, ALTER, DROP — tables, indexes, views, functions, …',
  admin: 'GRANT, roles, VACUUM, DO blocks, server files, SET ROLE, … and anything unrecognised',
};

export const VERB_LABEL: Record<Verb, string> = {
  select: 'SELECT',
  insert: 'INSERT',
  update: 'UPDATE',
  delete: 'DELETE',
  merge: 'MERGE',
  truncate: 'TRUNCATE',
  lock: 'row locks',
  function: 'side-effect functions',
  call: 'CALL',
  notify: 'NOTIFY',
  refresh: 'REFRESH',
  create: 'CREATE',
  alter: 'ALTER',
  drop: 'DROP',
  admin: 'admin',
};
export const VERB_DESCRIPTION: Partial<Record<Verb, string>> = {
  insert: 'add rows (also COPY FROM)',
  update: 'change rows (also the update half of an upsert)',
  delete: 'remove rows',
  merge: 'MERGE INTO …',
  truncate: 'empty whole tables',
  lock: 'SELECT … FOR UPDATE, LOCK TABLE',
  function: 'nextval(), volatile functions',
  call: 'stored procedures',
  notify: 'NOTIFY / pg_notify',
  refresh: 'REFRESH MATERIALIZED VIEW',
  create: 'tables, indexes, views, functions, …',
  alter: 'ALTER, RENAME, COMMENT',
  drop: 'DROP anything',
};

const MYSQL_OP_DESCRIPTION: Record<Operation, string> = {
  read: 'SELECT, SHOW, DESCRIBE, plain EXPLAIN',
  write: 'INSERT, REPLACE, UPDATE, DELETE, TRUNCATE, row and table locks, stored functions, CALL',
  ddl: 'CREATE, ALTER, DROP, RENAME — tables, indexes, views, procedures, …',
  admin: 'GRANT, users, SET GLOBAL, sql_mode, LOAD DATA, INTO OUTFILE, KILL, … and anything unrecognised',
};

const MYSQL_VERB_DESCRIPTION: Partial<Record<Verb, string>> = {
  insert: 'add rows (also REPLACE and INSERT … ON DUPLICATE KEY UPDATE)',
  update: 'change rows (also ON DUPLICATE KEY UPDATE)',
  delete: 'remove rows (also REPLACE)',
  lock: 'SELECT … FOR UPDATE / LOCK IN SHARE MODE, LOCK TABLES',
  function: 'stored functions, GET_LOCK(), sequences',
  alter: 'ALTER, RENAME TABLE',
};

/** Postgres-only statement kinds aren't offered for MySQL / MariaDB databases. */
const POSTGRES_ONLY = new Set<Verb>(['merge', 'notify', 'refresh']);

export const opDescription = (op: Operation, engine: Engine) => (isMysql(engine) ? MYSQL_OP_DESCRIPTION : OP_DESCRIPTION)[op];
export const verbDescription = (verb: Verb, engine: Engine) => (isMysql(engine) ? (MYSQL_VERB_DESCRIPTION[verb] ?? VERB_DESCRIPTION[verb]) : VERB_DESCRIPTION[verb]);
export const verbsFor = (op: Operation, engine: Engine): readonly Verb[] => (isMysql(engine) ? VERBS[op].filter((v) => !POSTGRES_ONLY.has(v)) : VERBS[op]);

/** Label for a rule/grant target: an operation ("write") or a verb ("DELETE"). */
export const targetLabel = (t: PolicyTarget) => (targetOperation(t) === t ? OP_LABEL[t as Operation] : VERB_LABEL[t as Verb]);

/** A chip for an operation or a verb, coloured by its operation. */
export function OpChip({ op }: { op: PolicyTarget }) {
  return <span className={`chip chip-${targetOperation(op)}`}>{targetLabel(op)}</span>;
}

/** "DELETE on orders", "read on app.users", "admin". */
export const describeAccess = (a: Access) =>
  `${a.op === 'read' || !a.verb || a.verb === a.op ? OP_LABEL[a.op] : VERB_LABEL[a.verb]}${a.table ? ` on ${a.table}` : ''}`;

export function ActionBadge({ action }: { action: Action }) {
  return <span className={`badge badge-${action}`}>{ACTION_LABEL[action]}</span>;
}

/** Segmented allow / ask / deny control. */
export function ActionPicker({ value, onChange }: { value: Action; onChange(a: Action): void }) {
  return (
    <div className="segmented">
      {(['allow', 'approve', 'deny'] as Action[]).map((a) => (
        <button key={a} type="button" className={value === a ? `on on-${a}` : ''} onClick={() => onChange(a)}>
          {ACTION_LABEL[a]}
        </button>
      ))}
    </div>
  );
}

export function StatusDot({ state }: { state?: string }) {
  return <span className={`dot dot-${state ?? 'idle'}`} title={state ?? 'idle'} />;
}

export function Code({ children }: { children: string }) {
  return <pre className="code">{children}</pre>;
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn small"
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? 'Copied' : label}
    </button>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children && <p>{children}</p>}
    </div>
  );
}

export function Modal({ title, onClose, children }: { title: string; onClose(): void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-label={title}>
        <header>
          <h2>{title}</h2>
          <button type="button" className="btn ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        {children}
      </div>
    </div>
  );
}

// ── time ──────────────────────────────────────────────────

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

export function relative(iso: string, now = Date.now()): string {
  const s = Math.round((new Date(iso).getTime() - now) / 1000);
  const abs = Math.abs(s);
  if (abs < 60) return rtf.format(s, 'second');
  if (abs < 3600) return rtf.format(Math.round(s / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(s / 3600), 'hour');
  return rtf.format(Math.round(s / 86400), 'day');
}

/** Seconds as a ticking clock: 4:05, 1:02:03, or 2d 01:02:03. */
export function clock(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const pad = (n: number) => String(n).padStart(2, '0');
  const [d, h, m, sec] = [Math.floor(s / 86400), Math.floor((s % 86400) / 3600), Math.floor((s % 3600) / 60), s % 60];
  if (d) return `${d}d ${pad(h)}:${pad(m)}:${pad(sec)}`;
  if (h) return `${h}:${pad(m)}:${pad(sec)}`;
  return `${m}:${pad(sec)}`;
}

/** Re-renders every `ms` so relative times and countdowns stay current. */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}

// ── errors ────────────────────────────────────────────────

const listeners = new Set<(msg: string) => void>();

/** Run an async action, surfacing failures as a toast. */
export async function attempt<T>(fn: () => Promise<T>): Promise<T | undefined> {
  try {
    return await fn();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    listeners.forEach((l) => l(msg));
    return undefined;
  }
}

export function Toasts() {
  const [items, setItems] = useState<{ id: number; msg: string }[]>([]);
  useEffect(() => {
    const on = (msg: string) => {
      const id = Date.now() + Math.random();
      setItems((cur) => [...cur, { id, msg }]);
      setTimeout(() => setItems((cur) => cur.filter((i) => i.id !== id)), 6000);
    };
    listeners.add(on);
    return () => void listeners.delete(on);
  }, []);
  return (
    <div className="toasts">
      {items.map((i) => (
        <div key={i.id} className="toast" onClick={() => setItems((cur) => cur.filter((x) => x.id !== i.id))}>
          {i.msg}
        </div>
      ))}
    </div>
  );
}
