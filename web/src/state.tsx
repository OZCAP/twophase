import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Api, type Approval, type AuditEntry, type Decision, type Grant, type Database, type ProxyStatus, type ProxyUser } from './api';

import { closeApprovalNotification, shareTokenWithServiceWorker, syncPushSubscription } from './push';

const TOKEN_KEY = 'twophase-admin-token';

interface ProxyState {
  api: Api;
  status: ProxyStatus | null;
  live: boolean;
  pending: Approval[];
  recent: Approval[];
  grants: Grant[];
  databases: Database[];
  users: ProxyUser[];
  activity: AuditEntry[];
  refreshStatus(): Promise<void>;
  refreshApprovals(): Promise<void>;
  refreshDatabases(): Promise<void>;
  refreshUsers(): Promise<void>;
  loadMoreActivity(): Promise<void>;
  decide(id: string, d: Decision): Promise<void>;
  logout(): void;
}

const Ctx = createContext<ProxyState | null>(null);

export function useProxy(): ProxyState {
  const v = useContext(Ctx);
  if (!v) throw new Error('useProxy outside ProxyProvider');
  return v;
}

export const savedToken = () => localStorage.getItem(TOKEN_KEY);
export function saveToken(t: string | null) {
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
  void shareTokenWithServiceWorker(t);
}

function upsert<T extends { id: unknown }>(list: T[], item: T, atStart = true): T[] {
  const rest = list.filter((x) => x.id !== item.id);
  return atStart ? [item, ...rest] : [...rest, item];
}

export function ProxyProvider({ token, onLogout, children }: { token: string; onLogout(): void; children: ReactNode }) {
  const api = useMemo(() => new Api(token), [token]);
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [live, setLive] = useState(false);
  const [pending, setPending] = useState<Approval[]>([]);
  const [recent, setRecent] = useState<Approval[]>([]);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [databases, setDatabases] = useState<Database[]>([]);
  const [users, setUsers] = useState<ProxyUser[]>([]);
  const [activity, setActivity] = useState<AuditEntry[]>([]);
  const activityRef = useRef(activity);
  activityRef.current = activity;

  const refreshApprovals = useCallback(async () => {
    const [p, r, g] = await Promise.all([api.approvals('pending'), api.approvals(undefined, 40), api.grants()]);
    setPending(p.sort((a, b) => a.createdAt.localeCompare(b.createdAt)));
    setRecent(r.filter((a) => a.status !== 'pending'));
    setGrants(g);
  }, [api]);
  const refreshStatus = useCallback(async () => setStatus(await api.status()), [api]);
  const refreshDatabases = useCallback(async () => setDatabases(await api.databases()), [api]);
  const refreshUsers = useCallback(async () => setUsers(await api.users()), [api]);
  const loadMoreActivity = useCallback(async () => {
    const last = activityRef.current.at(-1);
    const more = await api.audit(last?.id);
    setActivity((cur) => [...cur, ...more.filter((m) => !cur.some((c) => c.id === m.id))]);
  }, [api]);

  const resolved = useCallback((a: Approval) => {
    setPending((cur) => cur.filter((x) => x.id !== a.id));
    setRecent((cur) => upsert(cur, a));
    void closeApprovalNotification(a.id);
  }, []);

  const decide = useCallback(
    async (id: string, d: Decision) => {
      resolved(await api.decide(id, d));
      if (d.decision === 'approve' && d.scope && d.scope !== 'once') setGrants(await api.grants());
    },
    [api, resolved],
  );

  useEffect(() => {
    api.status().then(setStatus, (err) => err.status === 401 && onLogout());
    refreshApprovals().catch(() => {});
    refreshDatabases().catch(() => {});
    refreshUsers().catch(() => {});
    api.audit().then(setActivity, () => {});
    void shareTokenWithServiceWorker(token);
    syncPushSubscription(api).catch(() => {});
  }, [api, token, refreshApprovals, refreshDatabases, refreshUsers, onLogout]);

  // Coming back to the app (e.g. from a notification): the event stream may have died while it was
  // in the background (iOS suspends it), so reconnect, which also refetches pending approvals.
  const [resumed, setResumed] = useState(0);
  useEffect(() => {
    let hiddenAt = 0;
    const on = () => {
      if (document.visibilityState === 'hidden') hiddenAt = Date.now();
      else if (hiddenAt && Date.now() - hiddenAt > 2000) setResumed((n) => n + 1);
    };
    document.addEventListener('visibilitychange', on);
    return () => document.removeEventListener('visibilitychange', on);
  }, []);

  // Live updates with reconnect/backoff; refetch on (re)connect to catch anything missed.
  useEffect(() => {
    const ctrl = new AbortController();
    (async () => {
      let backoff = 1000;
      while (!ctrl.signal.aborted) {
        try {
          await api.streamEvents((name, data) => {
            switch (name) {
              case 'ready':
                setLive(true);
                backoff = 1000;
                refreshApprovals().catch(() => {});
                break;
              case 'approval.created':
                setPending((cur) => (cur.some((x) => x.id === data.id) ? cur : [...cur, data]));
                break;
              case 'approval.resolved':
                resolved(data);
                break;
              case 'grant.created':
                setGrants((cur) => upsert(cur, data));
                break;
              case 'grant.revoked':
                setGrants((cur) => cur.filter((g) => g.id !== data.id));
                break;
              case 'audit':
                setActivity((cur) => upsert(cur, data));
                break;
            }
          }, ctrl.signal);
        } catch {
          /* reconnect below */
        }
        setLive(false);
        if (ctrl.signal.aborted) return;
        await new Promise((r) => setTimeout(r, backoff));
        backoff = Math.min(backoff * 2, 30_000);
      }
    })();
    return () => ctrl.abort();
  }, [api, refreshApprovals, resolved, resumed]);

  useEffect(() => {
    document.title = pending.length ? `(${pending.length}) Twophase` : 'Twophase';
  }, [pending.length]);

  const value: ProxyState = {
    api,
    status,
    live,
    pending,
    recent,
    grants,
    databases,
    users,
    activity,
    refreshStatus,
    refreshApprovals,
    refreshDatabases,
    refreshUsers,
    loadMoreActivity,
    decide,
    logout: onLogout,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** Minimal hash router: `#/databases/abc` → ['databases', 'abc']. */
export function useRoute(): string[] {
  const read = () => location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const on = () => setRoute(read());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return route;
}

export const go = (path: string) => (location.hash = `#/${path}`);
