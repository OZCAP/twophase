import { useCallback, useEffect, useState } from 'react';
import { Api, ApiError } from './api';
import { ProxyProvider, savedToken, saveToken, useProxy, useRoute } from './state';
import { Toasts } from './ui';
import { ActivityView } from './views/Activity';
import { ApprovalsView } from './views/Approvals';
import { ClientsView } from './views/Clients';
import { DatabasesView } from './views/Databases';
import { Login, SettingsView } from './views/Settings';

type Gate =
  | { state: 'checking' }
  | { state: 'ready'; token: string } // '' = authenticated by Tailscale, no token
  | { state: 'login' }
  | { state: 'blocked'; message: string };

/** If the server authenticates via Tailscale, a token-less request already succeeds and no login is needed. */
async function detectAuth(): Promise<Gate> {
  try {
    const status = await new Api('').status();
    if (status.auth.mode === 'tailscale') {
      saveToken(null);
      return { state: 'ready', token: '' };
    }
  } catch (err) {
    if (err instanceof ApiError && err.status === 403) return { state: 'blocked', message: err.message };
  }
  const token = savedToken();
  return token ? { state: 'ready', token } : { state: 'login' };
}

export function App() {
  const [gate, setGate] = useState<Gate>({ state: 'checking' });
  useEffect(() => void detectAuth().then(setGate), []);

  const logout = useCallback(() => {
    saveToken(null);
    setGate({ state: 'checking' });
    void detectAuth().then(setGate);
  }, []);

  return (
    <>
      {gate.state === 'ready' && (
        <ProxyProvider token={gate.token} onLogout={logout}>
          <Shell />
        </ProxyProvider>
      )}
      {gate.state === 'login' && (
        <Login
          onLogin={(t) => {
            saveToken(t);
            setGate({ state: 'ready', token: t });
          }}
        />
      )}
      {gate.state === 'blocked' && (
        <div className="login">
          <div className="card">
            <h1>Not allowed</h1>
            <p>{gate.message}.</p>
            <p className="muted small">Ask the proxy's operator to add this device to ADMIN_TAILSCALE_ALLOW.</p>
          </div>
        </div>
      )}
      <Toasts />
    </>
  );
}

const TABS = [
  ['approvals', 'Approvals'],
  ['databases', 'Databases'],
  ['clients', 'Clients'],
  ['activity', 'Activity'],
  ['settings', 'Settings'],
] as const;

function Shell() {
  const { pending, live } = useProxy();
  const [tab = 'approvals', id] = useRoute();

  return (
    <div className="shell">
      <nav className="nav">
        <a href="#/approvals" className="brand">
          <img src="/icon.svg" width={22} height={22} alt="" /> Twophase
        </a>
        {TABS.map(([key, label]) => (
          <a key={key} href={`#/${key}`} className={tab === key ? 'active' : ''}>
            {label}
            {key === 'approvals' && pending.length > 0 && <span className="count">{pending.length}</span>}
          </a>
        ))}
        <span className="grow" />
        <span className="live" title={live ? 'Live updates connected' : 'Reconnecting…'}>
          <span className={`dot ${live ? 'dot-connected' : 'dot-idle'}`} /> {live ? 'Live' : 'Offline'}
        </span>
      </nav>
      <main className="main">
        {tab === 'approvals' && <ApprovalsView focusId={id} />}
        {tab === 'databases' && <DatabasesView databaseId={id} />}
        {tab === 'clients' && <ClientsView userId={id} />}
        {tab === 'activity' && <ActivityView />}
        {tab === 'settings' && <SettingsView />}
      </main>
    </div>
  );
}
