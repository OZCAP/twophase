import { useEffect, useState } from 'react';
import { Api, type AuthInfo } from '../api';
import { clearRefreshMarker, serviceWorkerVersion, currentSubscription, disablePush, enablePush, isIos, isStandalone, pushSupported, refreshApp } from '../push';
import { useProxy } from '../state';
import { attempt } from '../ui';

export function SettingsView() {
  const { api, status, live, logout } = useProxy();

  return (
    <div className="stack">
      <h2>Settings</h2>
      <section className="card">
        <dl className="facts">
          <dt>Server</dt>
          <dd className="mono">{location.origin}</dd>
          <dt>Version</dt>
          <dd>{status?.version ?? '…'}</dd>
          <dt>Live updates</dt>
          <dd>{live ? 'connected' : 'reconnecting…'}</dd>
          <dt>Postgres listener</dt>
          <dd className="mono">{status ? (status.wire.enabled ? `${location.hostname}:${status.wire.port}` : 'disabled') : '…'}</dd>
          <dt>MySQL listener</dt>
          <dd className="mono">{status ? (status.mysqlWire?.enabled ? `${location.hostname}:${status.mysqlWire.port}` : 'disabled') : '…'}</dd>
          <dt>Approval timeout</dt>
          <dd title="Set with APPROVAL_TIMEOUT_SECONDS">{status ? `${status.approvalTimeoutSeconds} seconds` : '…'}</dd>
          <dt>Signed in</dt>
          <dd>
            {status?.auth.mode === 'tailscale'
              ? `via Tailscale${status.auth.passwordRequired ? ' and password' : ''} as ${status.auth.device}${status.auth.login ? ` (${status.auth.login})` : ''}`
              : status
                ? status.auth.mode === 'password' ? 'with management password' : 'with admin token'
                : '…'}
          </dd>
          <dt>Push devices</dt>
          <dd>{status ? `${status.webPushSubscriptions} subscribed` : '…'}</dd>
        </dl>
      </section>
      <PushCard />
      <AppCard />
      {(status?.auth.mode !== 'tailscale' || status.auth.passwordRequired) && (
        <button
          className="btn deny"
          style={{ alignSelf: 'flex-start' }}
          onClick={async () => {
            // Stop sending approval details to this device once it's signed out.
            await disablePush(api).catch(() => {});
            logout();
          }}
        >
          Sign out
        </button>
      )}
    </div>
  );
}

/** Shown once after a refresh, then cleared from the address bar. */
const justRefreshed = clearRefreshMarker();

function AppCard() {
  const [busy, setBusy] = useState(false);
  const [worker, setWorker] = useState('…');
  useEffect(() => {
    void serviceWorkerVersion().then(setWorker);
  }, []);
  const built = new Date(__BUILD_TIME__);
  return (
    <section className="card">
      <h3>App</h3>
      <dl className="facts">
        <dt>This build</dt>
        <dd>
          {built.toLocaleString()} {justRefreshed && <span className="badge badge-allow">just refreshed</span>}
        </dd>
        <dt>Background worker</dt>
        <dd className="mono">{worker}</dd>
      </dl>
      <p className="muted small">
        Re-download the app and reload it, to pick up an update right away. Your sign-in and push notifications stay as they are.
      </p>
      <button
        className="btn"
        style={{ alignSelf: 'flex-start' }}
        disabled={busy}
        onClick={() => {
          setBusy(true);
          void refreshApp().catch(() => location.reload());
        }}
      >
        {busy ? 'Refreshing…' : 'Refresh app'}
      </button>
    </section>
  );
}

function PushCard() {
  const { api, refreshStatus } = useProxy();
  const [subscribed, setSubscribed] = useState<boolean | null>(null);
  const [permission, setPermission] = useState(pushSupported ? Notification.permission : 'default');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => {
    currentSubscription().then((s) => setSubscribed(!!s), () => setSubscribed(false));
  }, []);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setNote(null);
    await attempt(fn);
    setPermission(pushSupported ? Notification.permission : 'default');
    setSubscribed(!!(await currentSubscription().catch(() => null)));
    await refreshStatus().catch(() => {});
    setBusy(false);
  };

  return (
    <section className="card">
      <h3>Push notifications</h3>
      <p className="muted small">
        Get a notification on this device whenever a statement waits for approval, even when the app is closed. On desktop
        and Android you can approve or deny right from the notification.
      </p>

      {!pushSupported ? (
        isIos && !isStandalone ? (
          <p>
            On iPhone/iPad, push only works for the installed app: tap <strong>Share → Add to Home Screen</strong>, open MCP
            Proxy from your Home Screen, then enable notifications here.
          </p>
        ) : (
          <p className="muted">This browser doesn't support Web Push.</p>
        )
      ) : permission === 'denied' ? (
        <p className="error">Notifications are blocked for this site. Allow them in your browser's site settings.</p>
      ) : subscribed ? (
        <div className="row">
          <span className="grow">✅ Enabled on this device</span>
          <button
            className="btn"
            disabled={busy}
            onClick={() =>
              run(async () => {
                const r = await api.testPush();
                setNote(`Sent to ${r.sent} device${r.sent === 1 ? '' : 's'}${r.failed ? `, ${r.failed} failed` : ''}.`);
              })
            }
          >
            Send test
          </button>
          <button className="btn deny" disabled={busy} onClick={() => run(() => disablePush(api))}>
            Disable
          </button>
        </div>
      ) : (
        <button className="btn primary" disabled={busy || subscribed === null} onClick={() => run(() => enablePush(api))}>
          Enable push notifications
        </button>
      )}
      {note && <p className="muted small">{note}</p>}
    </section>
  );
}

export function Login({ info, onLogin }: { info: AuthInfo; onLogin(token: string): void }) {
  const [token, setToken] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  return (
    <div className="login">
      <form
        className="card form"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            const credential = info.mode === 'token' ? token.trim() : '';
            const api = new Api(credential);
            if (info.passwordRequired) await api.login(password);
            await api.status();
            setPassword('');
            onLogin(credential);
          } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        <img src="/icon.svg" width={48} height={48} alt="" />
        <h1>Twophase</h1>
        {info.mode === 'token' && <label>
          Admin token
          <input type="password" value={token} required autoFocus autoComplete="current-password" placeholder="tpa_…" onChange={(e) => setToken(e.target.value)} />
        </label>}
        {info.passwordRequired && <label>
          Management password
          <input type="password" value={password} required autoFocus={info.mode !== 'token'} autoComplete="current-password" onChange={(e) => setPassword(e.target.value)} />
        </label>}
        {info.mode === 'token' && <p className="muted small">Use the admin token configured by the proxy's operator.</p>}
        {info.mode === 'tailscale' && <p className="muted small">Enter the management password to continue.</p>}
        {error && <p className="error">{error}</p>}
        <button className="btn primary" disabled={busy}>
          Sign in
        </button>
      </form>
    </div>
  );
}
