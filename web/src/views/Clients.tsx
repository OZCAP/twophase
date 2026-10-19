import { useState } from 'react';
import { ENGINE_LABEL, isMysql, mysqlUrl, proxyHost, psqlUrl, wirePort, type Database, type DatabaseAccess, type IssuedToken, type ProxyUser } from '../api';
import { go, useProxy } from '../state';
import { attempt, Code, CopyButton, Empty, Modal, relative, TRUST_DURATIONS } from '../ui';
import { GrantRow } from './Approvals';

const surfaces = (a: DatabaseAccess, db?: Database) => [a.allowMcp && 'MCP', a.allowWire && (db ? ENGINE_LABEL[db.engine] : 'wire')].filter(Boolean).join(' + ') || 'no access';

export function ClientsView({ userId }: { userId?: string }) {
  const { users, databases } = useProxy();
  const [creating, setCreating] = useState(false);
  const [issued, setIssued] = useState<IssuedToken | null>(null);
  const selected = users.find((u) => u.id === userId);
  const dbName = (id: string) => databases.find((d) => d.id === id)?.name;

  return (
    <div className="stack">
      {selected ? (
        <ClientDetail user={selected} onIssued={setIssued} />
      ) : (
        <>
          <div className="row">
            <h2 className="grow">Clients</h2>
            <button className="btn primary" onClick={() => setCreating(true)} disabled={databases.length === 0}>
              New client
            </button>
          </div>
          <p className="muted small">
            Each client (an agent, a teammate, an app) gets one token. It works as the MCP bearer token and as the Postgres password, so every statement is
            attributed and can have its own rules.
          </p>
          {users.length === 0 ? (
            <Empty title="No clients yet">{databases.length === 0 ? 'Add a database first.' : 'Create one to get a token.'}</Empty>
          ) : (
            <ul className="list">
              {users.map((u) => (
                <li key={u.id} className="row clickable" onClick={() => go(`clients/${u.id}`)}>
                  <div className="grow">
                    <div>
                      <strong>{u.name}</strong> <span className="muted mono small">{u.username}</span> {!u.enabled && <span className="pill pill-denied">disabled</span>}
                    </div>
                    <div className="muted small ellipsis">
                      {u.access.map((a) => `${dbName(a.databaseId)} (${surfaces(a, databases.find((d) => d.id === a.databaseId))})`).join(', ') || 'no databases'}
                    </div>
                  </div>
                  <span className="muted small">{u.lastUsedAt ? `active ${relative(u.lastUsedAt)}` : 'never connected'}</span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {creating && (
        <NewClient
          databases={databases}
          onClose={() => setCreating(false)}
          onCreated={(t) => {
            setCreating(false);
            setIssued(t);
          }}
        />
      )}
      {issued && <TokenReveal issued={issued} databases={databases} onClose={() => setIssued(null)} />}
    </div>
  );
}

/** Per-database checkboxes: access at all, and which surfaces. */
function AccessEditor({ databases, access, onChange }: { databases: Database[]; access: DatabaseAccess[]; onChange(next: DatabaseAccess[]): void }) {
  const get = (id: string) => access.find((a) => a.databaseId === id);
  const set = (id: string, patch: Partial<DatabaseAccess> | null) => {
    const rest = access.filter((a) => a.databaseId !== id);
    if (patch === null) return onChange(rest);
    onChange([...rest, { databaseId: id, allowMcp: true, allowWire: true, ...get(id), ...patch }]);
  };
  return (
    <ul className="list">
      {databases.map((d) => {
        const a = get(d.id);
        return (
          <li key={d.id} className="access-row">
            <label className="check">
              <input type="checkbox" checked={!!a} onChange={(e) => set(d.id, e.target.checked ? {} : null)} /> <strong>{d.name}</strong>
            </label>
            <label className="check small" title="Hosted MCP tools (query, list_tables, …)">
              <input type="checkbox" disabled={!a} checked={!!a?.allowMcp} onChange={(e) => set(d.id, { allowMcp: e.target.checked })} /> MCP
            </label>
            <label className="check small" title={`Connect with ${isMysql(d.engine) ? 'the mysql client' : 'psql'}, apps and ORMs`}>
              <input type="checkbox" disabled={!a} checked={!!a?.allowWire} onChange={(e) => set(d.id, { allowWire: e.target.checked })} /> {ENGINE_LABEL[d.engine]}
            </label>
            <span />
          </li>
        );
      })}
    </ul>
  );
}

function ClientDetail({ user, onIssued }: { user: ProxyUser; onIssued(t: IssuedToken): void }) {
  const { api, databases, grants, refreshUsers } = useProxy();
  const [trustMinutes, setTrustMinutes] = useState<number | null>(10);
  const userGrants = grants.filter((g) => g.userId === user.id);

  const update = (patch: Parameters<typeof api.updateUser>[1]) =>
    attempt(async () => {
      await api.updateUser(user.id, patch);
      await refreshUsers();
    });

  return (
    <>
      <a href="#/clients" className="muted">
        ← Clients
      </a>
      <div className="row">
        <h2 className="grow">{user.name}</h2>
        <label className="check">
          <input type="checkbox" checked={user.enabled} onChange={(e) => update({ enabled: e.target.checked })} /> Enabled
        </label>
      </div>
      <div className="muted small">
        Login <span className="mono">{user.username}</span> · token <span className="mono">{user.tokenPrefix}…</span> · created {relative(user.createdAt)} ·{' '}
        {user.lastUsedAt ? `last connected ${relative(user.lastUsedAt)}` : 'never connected'}
      </div>
      {!user.mysqlLogin && user.access.some((a) => a.allowWire && databases.find((d) => d.id === a.databaseId && isMysql(d.engine))) && (
        <p className="warn small">This token predates MySQL support: it can't log in with a MySQL client until it's used once over MCP or rotated.</p>
      )}

      <section>
        <h3>Database access</h3>
        <AccessEditor databases={databases} access={user.access} onChange={(access) => update({ access })} />
      </section>

      {user.access.length > 0 && (
        <section>
          <h3>Trust window</h3>
          <p className="muted small">Skip “ask” for this client for a while. Deny rules still apply.</p>
          <div className="row">
            <select value={trustMinutes ?? ''} onChange={(e) => setTrustMinutes(e.target.value ? Number(e.target.value) : null)}>
              {TRUST_DURATIONS.map((d) => (
                <option key={d.label} value={d.minutes ?? ''}>
                  {d.label}
                </option>
              ))}
            </select>
            {user.access.map((a) => (
              <button
                key={a.databaseId}
                className="btn small"
                onClick={() => attempt(() => api.createGrant({ databaseId: a.databaseId, userId: user.id, operation: null, tablePattern: null, durationMinutes: trustMinutes }))}
              >
                Trust on {databases.find((d) => d.id === a.databaseId)?.name}
              </button>
            ))}
          </div>
        </section>
      )}

      {userGrants.length > 0 && (
        <section>
          <h3>Active trust windows</h3>
          <ul className="list">
            {userGrants.map((g) => (
              <GrantRow key={g.id} grant={g} />
            ))}
          </ul>
        </section>
      )}

      <section className="row">
        <button
          className="btn"
          onClick={async () => {
            if (!confirm(`Rotate ${user.name}'s token? The old one stops working for new connections and MCP sessions.`)) return;
            const t = await attempt(() => api.rotateToken(user.id));
            if (t) {
              await refreshUsers();
              onIssued(t);
            }
          }}
        >
          Rotate token
        </button>
        <span className="grow" />
        <button
          className="btn deny"
          onClick={async () => {
            if (!confirm(`Delete ${user.name}?`)) return;
            if (await attempt(async () => (await api.deleteUser(user.id), true))) {
              await refreshUsers();
              go('clients');
            }
          }}
        >
          Delete client
        </button>
      </section>
    </>
  );
}

function NewClient({ databases, onClose, onCreated }: { databases: Database[]; onClose(): void; onCreated(t: IssuedToken): void }) {
  const { api, refreshUsers } = useProxy();
  const [name, setName] = useState('');
  const [access, setAccess] = useState<DatabaseAccess[]>(databases.length === 1 ? [{ databaseId: databases[0].id, allowMcp: true, allowWire: true }] : []);

  return (
    <Modal title="New client" onClose={onClose}>
      <form
        className="form"
        onSubmit={async (e) => {
          e.preventDefault();
          const t = await attempt(() => api.createUser(name.trim(), access));
          if (t) {
            await refreshUsers();
            onCreated(t);
          }
        }}
      >
        <label>
          Name
          <input value={name} required autoFocus placeholder="claude-code-laptop" onChange={(e) => setName(e.target.value)} />
        </label>
        <div>
          <div className="muted small" style={{ marginBottom: 6 }}>
            Databases it may use, and how
          </div>
          <AccessEditor databases={databases} access={access} onChange={setAccess} />
        </div>
        <div className="row">
          <span className="grow" />
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary">Create</button>
        </div>
      </form>
    </Modal>
  );
}

function TokenReveal({ issued, databases, onClose }: { issued: IssuedToken; databases: Database[]; onClose(): void }) {
  const { status } = useProxy();
  const byId = new Map(databases.map((d) => [d.id, d]));
  const mcpDbs = issued.user.access.filter((a) => a.allowMcp).map((a) => byId.get(a.databaseId)!).filter(Boolean);
  const wireDbs = issued.user.access.filter((a) => a.allowWire).map((a) => byId.get(a.databaseId)!).filter(Boolean);

  const json = JSON.stringify(
    { mcpServers: Object.fromEntries(mcpDbs.map((d) => [d.slug, { type: 'http', url: `${location.origin}/mcp/${d.slug}`, headers: { Authorization: `Bearer ${issued.token}` } }])) },
    null,
    2,
  );
  const cli = mcpDbs.map((d) => `claude mcp add --transport http ${d.slug} ${location.origin}/mcp/${d.slug} \\\n  --header "Authorization: Bearer ${issued.token}"`).join('\n\n');
  const pgDbs = wireDbs.filter((d) => !isMysql(d.engine));
  const myDbs = wireDbs.filter((d) => isMysql(d.engine));
  const psql = pgDbs.map((d) => `psql "${psqlUrl(issued.user.username, issued.token, d.slug, wirePort(status, d.engine))}"`).join('\n');
  const mysqlCli = myDbs
    .map((d) => `${d.engine === 'mariadb' ? 'mariadb' : 'mysql'} -h ${proxyHost()} -P ${wirePort(status, d.engine)} -u ${issued.user.username} -p ${d.slug}`)
    .join('\n');
  const mysqlUrls = myDbs.map((d) => mysqlUrl(issued.user.username, issued.token, d.slug, wirePort(status, d.engine))).join('\n');

  return (
    <Modal title={`Token for ${issued.user.name}`} onClose={onClose}>
      <div className="stack">
        <p className="warn">This token is shown only once. Copy it now.</p>
        <div className="row">
          <code className="mono grow token">{issued.token}</code>
          <CopyButton text={issued.token} />
        </div>
        {myDbs.length > 0 && (
          <>
            <div className="row">
              <h3 className="grow">MySQL / MariaDB connection</h3>
              <CopyButton text={mysqlCli} />
            </div>
            <p className="muted small">
              User <span className="mono">{issued.user.username}</span>, password = the token (paste it at the prompt). For apps and ORMs:
            </p>
            <Code>{mysqlCli}</Code>
            <div className="row">
              <span className="grow muted small">Connection URL</span>
              <CopyButton text={mysqlUrls} />
            </div>
            <Code>{mysqlUrls}</Code>
          </>
        )}
        {pgDbs.length > 0 && (
          <>
            <div className="row">
              <h3 className="grow">Postgres connection</h3>
              <CopyButton text={psql} />
            </div>
            <p className="muted small">
              User <span className="mono">{issued.user.username}</span>, password = the token. Works with psql, ORMs and drivers (use sslmode=disable or prefer; traffic
              is protected by the tailnet).
            </p>
            <Code>{psql}</Code>
          </>
        )}
        {mcpDbs.length > 0 && (
          <>
            <div className="row">
              <h3 className="grow">MCP client config (.mcp.json)</h3>
              <CopyButton text={json} />
            </div>
            <Code>{json}</Code>
            <div className="row">
              <h3 className="grow">Claude Code</h3>
              <CopyButton text={cli} />
            </div>
            <Code>{cli}</Code>
          </>
        )}
        <div className="row">
          <span className="grow" />
          <button className="btn primary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </Modal>
  );
}
