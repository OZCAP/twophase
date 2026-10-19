import { useCallback, useEffect, useState } from 'react';
import { DEFAULT_PORT, defaultKey, ENGINE_LABEL, ENGINES, isMysql, OPERATIONS, proxyHost, VERBS, wireEnabled, wirePort, type Engine, type Action, type ConnectionTest, type Database, type DatabaseDraft, type Operation, type PolicyTarget, type Rule, type TableInfo, type Verb } from '../api';
import { go, useProxy } from '../state';
import { ACTION_LABEL, ActionBadge, ActionPicker, attempt, CopyButton, Empty, Modal, OP_LABEL, OpChip, opDescription, VERB_LABEL, verbDescription, verbsFor } from '../ui';

export function DatabasesView({ databaseId }: { databaseId?: string }) {
  const { databases } = useProxy();
  const [creating, setCreating] = useState(false);
  const selected = databases.find((d) => d.id === databaseId);
  if (databaseId && selected) return <DatabaseDetail db={selected} />;

  return (
    <div className="stack">
      <div className="row">
        <h2 className="grow">Databases</h2>
        <button className="btn primary" onClick={() => setCreating(true)}>
          Add database
        </button>
      </div>
      {databases.length === 0 ? (
        <Empty title="No databases yet">Add a Postgres, MySQL or MariaDB database. Clients then reach it through the proxy's MCP, or with their usual client as if it were the database itself.</Empty>
      ) : (
        <ul className="list">
          {databases.map((d) => (
            <li key={d.id} className="row clickable" onClick={() => go(`databases/${d.id}`)}>
              <div className="grow">
                <div>
                  <strong>{d.name}</strong> <span className="muted mono">{d.slug}</span> <span className="pill">{ENGINE_LABEL[d.engine]}</span>
                  {!d.enabled && <span className="pill">disabled</span>}
                </div>
                <div className="muted small mono ellipsis">
                  {d.user}@{d.host}:{d.port}/{d.database}
                </div>
              </div>
              <DefaultsSummary db={d} />
            </li>
          ))}
        </ul>
      )}
      {creating && <DatabaseEditor onClose={() => setCreating(false)} />}
    </div>
  );
}

function DefaultsSummary({ db }: { db: Database }) {
  return (
    <span className="row small" style={{ gap: 4, flexWrap: 'nowrap' }}>
      {OPERATIONS.map((op) => (
        <span key={op} title={`${op}: ${db[defaultKey(op)]}`} className={`badge badge-${db[defaultKey(op)]}`} style={{ marginLeft: 0 }}>
          {op === 'ddl' ? 'DDL' : op[0].toUpperCase() + op.slice(1)}
        </span>
      ))}
    </span>
  );
}

function DatabaseDetail({ db }: { db: Database }) {
  const { api, users, status, refreshDatabases } = useProxy();
  const [editing, setEditing] = useState(false);
  const [rules, setRules] = useState<Rule[]>([]);
  const [tables, setTables] = useState<TableInfo[] | null>(null);
  const [tablesError, setTablesError] = useState<string | null>(null);
  const [test, setTest] = useState<ConnectionTest | null>(null);
  const [ruleEditor, setRuleEditor] = useState<Rule | Partial<Rule> | null>(null);

  const load = useCallback(async () => {
    setRules(await api.rules(db.id));
    try {
      setTables(await api.tables(db.id));
      setTablesError(null);
    } catch (err) {
      setTables(null);
      setTablesError(err instanceof Error ? err.message : String(err));
    }
  }, [api, db.id]);

  useEffect(() => {
    void attempt(load);
    void api.testDatabase(db.id).then(setTest, () => {});
  }, [load, api, db.id]);

  const setDefault = (op: Operation, action: Action) =>
    attempt(async () => {
      await api.updateDatabase(db.id, { [defaultKey(op)]: action });
      await refreshDatabases();
      await load();
    });

  /** A verb default is an everyone, any-table rule for that verb; "Default" removes it. */
  const verbRule = (verb: Verb) => rules.find((r) => r.userId === null && r.tablePattern === null && r.operation === verb);
  const setVerbDefault = (verb: Verb, action: Action | null) =>
    attempt(async () => {
      const existing = verbRule(verb);
      if (action === null) {
        if (existing) await api.deleteRule(existing.id);
      } else if (existing) await api.updateRule(existing.id, { action });
      else await api.createRule({ databaseId: db.id, userId: null, operation: verb, tablePattern: null, action, note: null });
      await load();
    });

  const mcpUrl = `${location.origin}/mcp/${db.slug}`;
  const wireEndpoint = `${proxyHost()}:${wirePort(status, db.engine)}/${db.slug}`;
  const engine = ENGINE_LABEL[db.engine];

  return (
    <div className="stack">
      <a href="#/databases" className="muted">
        ← Databases
      </a>
      <div className="row">
        <h2 className="grow">{db.name}</h2>
        <button className="btn" onClick={() => attempt(async () => setTest(await api.testDatabase(db.id)))}>
          Test connection
        </button>
        <button className="btn" onClick={() => setEditing(true)}>
          Edit
        </button>
      </div>

      <section className="card">
        <dl className="kv">
          <dt>Connects as</dt>
          <dd className="mono">
            {db.user}@{db.host}:{db.port}/{db.database}
          </dd>
          <dt>TLS</dt>
          <dd>{db.sslmode}</dd>
          {db.readonlyUser && (
            <>
              <dt>Read-only login</dt>
              <dd className="mono">{db.readonlyUser}</dd>
            </>
          )}
          <dt>Limits</dt>
          <dd>
            {db.statementTimeoutMs / 1000}s per statement · {db.maxRows} rows per MCP result
          </dd>
          <dt>Status</dt>
          <dd>
            {!test ? (
              'checking…'
            ) : test.ok ? (
              <span className="badge badge-allow" style={{ marginLeft: 0 }}>
                connected · {/mariadb/i.test(test.serverVersion ?? '') ? '' : `${engine} `}
                {test.serverVersion}
              </span>
            ) : (
              <span className="error">{test.error}</span>
            )}
          </dd>
        </dl>
        {test?.warnings?.map((w) => (
          <p key={w} className="warn small">
            ⚠ {w}
          </p>
        ))}
      </section>

      <section className="card">
        <h3>Client endpoints</h3>
        <div className="row">
          <div className="grow">
            <div className="muted small">Hosted MCP</div>
            <div className="mono ellipsis">{mcpUrl}</div>
          </div>
          <CopyButton text={mcpUrl} />
        </div>
        {wireEnabled(status, db.engine) && (
          <div className="row">
            <div className="grow">
              <div className="muted small">
                {engine} ({isMysql(db.engine) ? 'mysql' : 'psql'}, apps, ORMs) — user and password come from a client
              </div>
              <div className="mono ellipsis">{wireEndpoint}</div>
            </div>
            <CopyButton text={wireEndpoint} />
          </div>
        )}
      </section>

      <section>
        <h3>Defaults</h3>
        <p className="muted small">
          What happens to each kind of statement when no rule matches.{' '}
          {isMysql(db.engine)
            ? 'Statements are classified the way MySQL reads them: quoting, comments and executable comments included.'
            : "Statements are classified with Postgres's own parser."}
        </p>
        <ul className="list">
          {OPERATIONS.map((op) => (
            <li key={op}>
              <div className="row tool-row" style={{ flexWrap: 'nowrap' }}>
                <div className="grow">
                  <OpChip op={op} /> <span className="muted small">{opDescription(op, db.engine)}</span>
                </div>
                <ActionPicker value={db[defaultKey(op)]} onChange={(a) => setDefault(op, a)} />
              </div>
              {(op === 'write' || op === 'ddl') && (
                <details className="verbs" open={VERBS[op].some((v) => verbRule(v))}>
                  <summary className="muted small">Fine-tune by statement type</summary>
                  <ul className="verb-list">
                    {verbsFor(op, db.engine).map((verb) => {
                      const rule = verbRule(verb);
                      return (
                        <li key={verb} className="row tool-row">
                          <div className="grow">
                            <OpChip op={verb} /> <span className="muted small">{verbDescription(verb, db.engine)}</span>
                          </div>
                          <VerbPicker value={rule?.action ?? null} inherited={db[defaultKey(op)]} onChange={(a) => setVerbDefault(verb, a)} />
                        </li>
                      );
                    })}
                  </ul>
                </details>
              )}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <div className="row">
          <h3 className="grow">Rules</h3>
          <button className="btn" onClick={() => setRuleEditor({})}>
            Add rule
          </button>
        </div>
        <p className="muted small">
          Most specific wins: a client-specific rule beats an everyone rule; an exact table beats a pattern beats “any table”. Ties go to the stricter action.
          A statement gets the strictest decision of everything it touches.
        </p>
        {rules.length === 0 ? (
          <p className="muted">No rules — the defaults above apply.</p>
        ) : (
          <ul className="list">
            {rules.map((r) => (
              <li key={r.id} className="row clickable" onClick={() => setRuleEditor(r)}>
                <OpChip op={r.operation} />
                <span className="mono grow ellipsis">{r.tablePattern ?? <span className="muted">any table</span>}</span>
                <span className="muted small">{r.userName ?? 'Everyone'}</span>
                <ActionBadge action={r.action} />
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h3>Tables</h3>
        {tablesError && <p className="error">Couldn't list tables: {tablesError}</p>}
        {tables === null && !tablesError && <p className="muted">Loading…</p>}
        {tables && tables.length === 0 && <p className="muted">No tables found.</p>}
        {tables && tables.length > 0 && (
          <ul className="list">
            {tables.map((t) => {
              const name = t.schema === 'public' ? t.name : `${t.schema}.${t.name}`;
              return (
                <li key={`${t.schema}.${t.name}`} className="row tool-row">
                  <div className="grow">
                    <strong className="mono">{name}</strong>
                    <span className="muted small">
                      {' '}
                      · {t.kind}
                      {t.estimatedRows !== null && ` · ~${t.estimatedRows.toLocaleString()} rows`}
                    </span>
                    {t.comment && <div className="muted small clamp">{t.comment}</div>}
                  </div>
                  <span className="row" style={{ gap: 6 }}>
                    {(['read', 'write', 'ddl'] as const).map((op) => (
                      <button key={op} className="btn ghost small" title={`Add a rule for ${op} on ${name}`} onClick={() => setRuleEditor({ operation: op, tablePattern: name })}>
                        <span className="muted">{op === 'ddl' ? 'DDL' : op}</span> <ActionBadge action={t.actions[op]} />
                      </button>
                    ))}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {editing && <DatabaseEditor db={db} onClose={() => setEditing(false)} />}
      {ruleEditor && (
        <RuleEditor
          databaseId={db.id}
          engine={db.engine}
          rule={ruleEditor}
          tableNames={tables?.map((t) => (t.schema === 'public' || (isMysql(db.engine) && t.schema === db.database) ? t.name : `${t.schema}.${t.name}`)) ?? []}
          users={users}
          onClose={() => setRuleEditor(null)}
          onSaved={() => attempt(load)}
        />
      )}
    </div>
  );
}

const slugify = (n: string) =>
  n
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 63);

function DatabaseEditor({ db, onClose }: { db?: Database; onClose(): void }) {
  const { api, refreshDatabases } = useProxy();
  const [f, setF] = useState({
    engine: (db?.engine ?? 'postgres') as Engine,
    name: db?.name ?? '',
    slug: db?.slug ?? '',
    host: db?.host ?? '',
    port: String(db?.port ?? DEFAULT_PORT.postgres),
    database: db?.database ?? '',
    user: db?.user ?? '',
    password: '',
    sslmode: db?.sslmode ?? 'prefer',
    readonlyUser: db?.readonlyUser ?? '',
    readonlyPassword: '',
    timeout: String((db?.statementTimeoutMs ?? 30_000) / 1000),
    maxRows: String(db?.maxRows ?? 200),
    enabled: db?.enabled ?? true,
  });
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF((cur) => ({ ...cur, [k]: e.target.value }));

  const save = async () => {
    setBusy(true);
    const draft: Partial<DatabaseDraft> = {
      engine: f.engine,
      name: f.name,
      slug: f.slug,
      host: f.host.trim(),
      port: Number(f.port),
      database: f.database.trim(),
      user: f.user.trim(),
      sslmode: f.sslmode as Database['sslmode'],
      readonlyUser: f.readonlyUser.trim() || null,
      statementTimeoutMs: Math.round(Number(f.timeout) * 1000),
      maxRows: Number(f.maxRows),
      enabled: f.enabled,
      ...(f.password || !db ? { password: f.password } : {}),
      ...(f.readonlyPassword ? { readonlyPassword: f.readonlyPassword } : {}),
    };
    const saved = await attempt(() => (db ? api.updateDatabase(db.id, draft) : api.createDatabase(draft)));
    setBusy(false);
    if (!saved) return;
    await refreshDatabases();
    onClose();
    if (!db) go(`databases/${saved.id}`);
  };

  const remove = async () => {
    if (!db || !confirm(`Remove ${db.name} from the proxy? Its rules, trust windows and client access are deleted. The database itself is untouched.`)) return;
    if (await attempt(async () => (await api.deleteDatabase(db.id), true))) {
      await refreshDatabases();
      onClose();
      go('databases');
    }
  };

  return (
    <Modal title={db ? `Edit ${db.name}` : 'Add database'} onClose={onClose}>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <label>
          Engine
          <select
            value={f.engine}
            onChange={(e) => {
              const engine = e.target.value as Engine;
              // Follow the engine's default port unless one was typed.
              setF((cur) => ({ ...cur, engine, port: cur.port === String(DEFAULT_PORT[cur.engine]) ? String(DEFAULT_PORT[engine]) : cur.port }));
            }}
          >
            {ENGINES.map((e) => (
              <option key={e} value={e}>
                {ENGINE_LABEL[e]}
              </option>
            ))}
          </select>
        </label>
        {isMysql(f.engine) && (
          <p className="muted small" style={{ marginTop: -6 }}>
            Postgres-compatible databases (Supabase, Neon, Timescale, CockroachDB, …) use Postgres; Aurora MySQL, PlanetScale and TiDB use MySQL.
          </p>
        )}
        <label>
          Name
          <input
            value={f.name}
            required
            placeholder="Production"
            onChange={(e) => setF((cur) => ({ ...cur, name: e.target.value, slug: !db && cur.slug === slugify(cur.name) ? slugify(e.target.value) : cur.slug }))}
          />
        </label>
        <label>
          Slug <span className="muted small">— the database name clients connect to</span>
          <input value={f.slug} required pattern="[a-z0-9][a-z0-9_\-]{0,62}" onChange={set('slug')} />
        </label>
        <div className="row" style={{ alignItems: 'flex-end' }}>
          <label className="grow">
            Host
            <input value={f.host} required placeholder="db.internal" onChange={set('host')} />
          </label>
          <label style={{ width: 100 }}>
            Port
            <input value={f.port} required inputMode="numeric" pattern="\d+" onChange={set('port')} />
          </label>
        </div>
        <label>
          Database
          <input value={f.database} required placeholder="app" onChange={set('database')} />
        </label>
        <div className="row" style={{ alignItems: 'flex-end' }}>
          <label className="grow">
            User
            <input value={f.user} required autoComplete="off" onChange={set('user')} />
          </label>
          <label className="grow">
            Password
            <input type="password" value={f.password} autoComplete="new-password" placeholder={db?.hasPassword ? '•••••• (unchanged)' : ''} onChange={set('password')} />
          </label>
        </div>
        <p className="muted small" style={{ marginTop: -6 }}>
          {isMysql(f.engine)
            ? 'Use a dedicated user with privileges on this database only — never root or *.* grants. Clients never see these credentials.'
            : "Use a dedicated role with only the privileges you'd ever approve — never a superuser. Clients never see these credentials."}
        </p>
        <label>
          TLS to the database
          <select value={f.sslmode} onChange={set('sslmode')}>
            <option value="disable">disable</option>
            <option value="prefer">prefer</option>
            <option value="require">require (no certificate check)</option>
            <option value="verify-full">verify-full</option>
          </select>
        </label>
        <details>
          <summary className="muted">Read-only login and limits</summary>
          <div className="form" style={{ marginTop: 12 }}>
            <p className="muted small">
              Optional: a login with only SELECT. Wire connections from clients that can never write use it, enforced by the database itself.
            </p>
            <div className="row" style={{ alignItems: 'flex-end' }}>
              <label className="grow">
                Read-only user
                <input value={f.readonlyUser} autoComplete="off" onChange={set('readonlyUser')} />
              </label>
              <label className="grow">
                Password
                <input type="password" value={f.readonlyPassword} autoComplete="new-password" placeholder={db?.hasReadonlyPassword ? '•••••• (unchanged)' : ''} onChange={set('readonlyPassword')} />
              </label>
            </div>
            <div className="row" style={{ alignItems: 'flex-end' }}>
              <label className="grow">
                Statement timeout (s)
                <input value={f.timeout} inputMode="decimal" onChange={set('timeout')} />
              </label>
              <label className="grow">
                Max rows per MCP result
                <input value={f.maxRows} inputMode="numeric" onChange={set('maxRows')} />
              </label>
            </div>
          </div>
        </details>
        <label className="check">
          <input type="checkbox" checked={f.enabled} onChange={(e) => setF((cur) => ({ ...cur, enabled: e.target.checked }))} /> Enabled
        </label>
        <div className="row">
          {db && (
            <button type="button" className="btn deny" onClick={remove}>
              Remove
            </button>
          )}
          <span className="grow" />
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={busy}>
            {db ? 'Save' : 'Add database'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function RuleEditor({
  databaseId,
  engine,
  rule,
  tableNames,
  users,
  onClose,
  onSaved,
}: {
  databaseId: string;
  engine: Engine;
  rule: Rule | Partial<Rule>;
  tableNames: string[];
  users: { id: string; name: string }[];
  onClose(): void;
  onSaved(): void;
}) {
  const { api } = useProxy();
  const existing = 'id' in rule && rule.id ? (rule as Rule) : null;
  const [operation, setOperation] = useState<PolicyTarget>(rule.operation ?? 'write');
  const [table, setTable] = useState(rule.tablePattern ?? '');
  const [userId, setUserId] = useState<string | null>(rule.userId ?? null);
  const [action, setAction] = useState<Action>(rule.action ?? 'approve');
  const [note, setNote] = useState(rule.note ?? '');

  const save = async () => {
    const body = { userId, operation, tablePattern: table.trim() || null, action, note: note.trim() || null };
    const ok = await attempt(() => (existing ? api.updateRule(existing.id, body) : api.createRule({ databaseId, ...body })));
    if (ok) {
      onSaved();
      onClose();
    }
  };

  return (
    <Modal title={existing ? 'Edit rule' : 'Add rule'} onClose={onClose}>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <label>
          Statements
          <select value={operation} onChange={(e) => setOperation(e.target.value as PolicyTarget)}>
            {OPERATIONS.map((op) => (
              <optgroup key={op} label={OP_LABEL[op]}>
                <option value={op}>
                  {op === 'admin' ? 'admin' : `any ${OP_LABEL[op]}`} — {opDescription(op, engine)}
                </option>
                {op !== 'read' &&
                  op !== 'admin' &&
                  verbsFor(op, engine).map((verb) => (
                    <option key={verb} value={verb}>
                      {VERB_LABEL[verb]} — {verbDescription(verb, engine)}
                    </option>
                  ))}
              </optgroup>
            ))}
          </select>
        </label>
        <label>
          Table <span className="muted small">— name or pattern (audit_*, app.*); empty = any table</span>
          <input value={table} list="table-names" placeholder="any table" onChange={(e) => setTable(e.target.value)} />
          <datalist id="table-names">
            {tableNames.map((t) => (
              <option key={t} value={t} />
            ))}
          </datalist>
        </label>
        <label>
          Applies to
          <select value={userId ?? ''} onChange={(e) => setUserId(e.target.value || null)}>
            <option value="">Everyone</option>
            {users.map((u) => (
              <option key={u.id} value={u.id}>
                {u.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Action
          <ActionPicker value={action} onChange={setAction} />
        </label>
        <label>
          Note <span className="muted small">— shown to the client when this rule denies</span>
          <input value={note} placeholder="optional" onChange={(e) => setNote(e.target.value)} />
        </label>
        <div className="row">
          {existing && (
            <button
              type="button"
              className="btn deny"
              onClick={async () => {
                await attempt(() => api.deleteRule(existing.id));
                onSaved();
                onClose();
              }}
            >
              Delete
            </button>
          )}
          <span className="grow" />
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary">Save</button>
        </div>
      </form>
    </Modal>
  );
}

/** Allow / Ask / Deny for one verb, or "Default" to follow its operation's setting. */
function VerbPicker({ value, inherited, onChange }: { value: Action | null; inherited: Action; onChange(a: Action | null): void }) {
  return (
    <div className="segmented">
      <button type="button" className={value === null ? 'on on-inherit' : ''} onClick={() => onChange(null)} title="Use the operation's default">
        Default ({ACTION_LABEL[inherited]})
      </button>
      {(['allow', 'approve', 'deny'] as Action[]).map((a) => (
        <button key={a} type="button" className={value === a ? `on on-${a}` : ''} onClick={() => onChange(a)}>
          {ACTION_LABEL[a]}
        </button>
      ))}
    </div>
  );
}
