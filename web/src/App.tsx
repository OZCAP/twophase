import { useCallback, useEffect, useState } from 'react';
import { Api } from './api';
import { detectAuth, type AuthGate } from './auth';
import { ProxyProvider, savedToken, saveToken, useProxy, useRoute } from './state';
import { Toasts } from './ui';
import { ActivityView } from './views/Activity';
import { ApprovalsView } from './views/Approvals';
import { ClientsView } from './views/Clients';
import { DatabasesView } from './views/Databases';
import { Login, SettingsView } from './views/Settings';

export function App() {
  const [gate, setGate] = useState<AuthGate>({ state: 'checking' });
  const check = useCallback(() => {
    void detectAuth(savedToken()).then((next) => {
      if (next.state === 'ready' && next.info.mode !== 'token') saveToken(null);
      setGate(next);
    });
  }, []);
  useEffect(check, [check]);

  const logout = useCallback(() => {
    setGate({ state: 'checking' });
    const request = gate.state === 'ready' && gate.info.passwordRequired ? new Api(gate.token).logout() : Promise.resolve();
    void request.catch(() => {}).then(() => { saveToken(null); check(); });
  }, [gate, check]);

  return (
    <>
      {gate.state === 'ready' && (
        <ProxyProvider token={gate.token} onLogout={logout}>
          <Shell />
        </ProxyProvider>
      )}
      {gate.state === 'login' && (
        <Login
          info={gate.info}
          onLogin={(t) => {
            saveToken(t || null);
            check();
          }}
        />
      )}
      {gate.state === 'blocked' && (
        <div className="login">
          <div className="card">
            <h1>Not allowed</h1>
            <p>{gate.message}.</p>
            <p className="muted small">Connect through Tailscale and check that its access rules allow this device to reach the proxy.</p>
            <button className="btn" onClick={check}>Try again</button>
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
