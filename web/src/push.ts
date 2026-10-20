import type { Api } from './api';

/** Web Push needs a service worker, the Push API and notifications. */
export const pushSupported = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;

/** iOS/iPadOS only allow Web Push for apps added to the Home Screen. */
export const isIos = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
export const isStandalone =
  window.matchMedia('(display-mode: standalone)').matches || (navigator as { standalone?: boolean }).standalone === true;

/** How long a tapped notification's target stays valid if the app only wakes up later. */
const PENDING_NAVIGATION_MS = 5 * 60_000;

/** Report a step to the proxy's diagnostics log (GET /admin/api/client-log). Never throws. */
export function clientLog(event: string, detail?: Record<string, unknown>) {
  const token = localStorage.getItem('twophase-admin-token');
  void fetch('/admin/api/client-log', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token && { authorization: `Bearer ${token}` }) },
    body: JSON.stringify({ source: 'page', event, detail: { hash: location.hash, visibility: document.visibilityState, ...detail } }),
    keepalive: true,
  }).catch(() => {});
}

interface NavigateRequest {
  url: string;
  nonce?: string;
  at?: number;
}

const handledNonces = new Set<string>();
const channel = 'BroadcastChannel' in window ? new BroadcastChannel('twophase') : null;

/** Go to a tapped notification's target (once per tap), and tell the service worker it worked. */
function handleNavigate(req: NavigateRequest, via: string) {
  if (req.nonce && handledNonces.has(req.nonce)) return;
  if (req.nonce) handledNonces.add(req.nonce);
  const from = location.hash;
  const target = new URL(req.url, location.origin);
  if (target.origin === location.origin && target.hash && location.hash !== target.hash) location.hash = target.hash;
  void kv('readwrite', (s) => s.delete('pendingNavigation')).catch(() => {});
  const ack = { type: 'navigated', nonce: req.nonce };
  channel?.postMessage(ack);
  navigator.serviceWorker?.controller?.postMessage(ack);
  clientLog('navigate', { via, from, to: target.hash });
}

async function consumePendingNavigation(via: string) {
  const pending = await kv<NavigateRequest>('readonly', (s) => s.get('pendingNavigation')).catch(() => undefined);
  if (!pending) return false;
  if (Date.now() - (pending.at ?? 0) < PENDING_NAVIGATION_MS) handleNavigate(pending, via);
  else await kv('readwrite', (s) => s.delete('pendingNavigation')).catch(() => {});
  return true;
}

/** iOS can show the page before the service worker's click handler has stored the target: keep looking briefly. */
function lookForPendingNavigation(via: string) {
  let tries = 0;
  const delays = [0, 250, 600, 1200, 2500, 4000];
  const next = () => {
    void consumePendingNavigation(via).then((found) => {
      if (!found && ++tries < delays.length) setTimeout(next, delays[tries] - delays[tries - 1]);
    });
  };
  next();
}

/** Which service worker version is in control of this page ('none', or 'old' if it doesn't answer). */
export async function serviceWorkerVersion(): Promise<string> {
  const sw = navigator.serviceWorker?.controller;
  if (!sw) return 'none';
  return new Promise((resolve) => {
    const on = (e: MessageEvent) => {
      if (e.data?.type !== 'version') return;
      navigator.serviceWorker.removeEventListener('message', on);
      resolve(String(e.data.v));
    };
    navigator.serviceWorker.addEventListener('message', on);
    sw.postMessage({ type: 'version' });
    setTimeout(() => {
      navigator.serviceWorker.removeEventListener('message', on);
      resolve('old (no answer)');
    }, 1500);
  });
}

async function workerState() {
  const reg = await navigator.serviceWorker.getRegistration().catch(() => undefined);
  return { sw: await serviceWorkerVersion(), waiting: !!reg?.waiting, installing: !!reg?.installing, active: reg?.active?.state ?? null };
}

export async function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  // A tapped notification reaches the page three ways (whichever iOS delivers): a message from the
  // service worker, the BroadcastChannel, and a target left in IndexedDB.
  navigator.serviceWorker.addEventListener('message', (e) => {
    if (e.data?.type === 'navigate' && typeof e.data.url === 'string') handleNavigate(e.data, 'sw message');
  });
  channel?.addEventListener('message', (e) => {
    if (e.data?.type === 'navigate' && typeof e.data.url === 'string') handleNavigate(e.data, 'broadcast');
  });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') return;
    void workerState().then((w) => clientLog('visible', w));
    lookForPendingNavigation('pending (visible)');
  });
  window.addEventListener('focus', () => lookForPendingNavigation('pending (focus)'));
  void workerState().then((w) => clientLog('load', { standalone: isStandalone, ...w }));
  lookForPendingNavigation('pending (load)');
  await navigator.serviceWorker.register('/sw.js');
}

/**
 * Force the installed app to the latest version: fetch a fresh service worker and let it take
 * over, drop any cached responses, re-download the page itself (bypassing the HTTP cache), then
 * reload. The service worker stays registered, so push notifications keep working.
 */
export async function refreshApp(): Promise<void> {
  const reg = await navigator.serviceWorker?.getRegistration().catch(() => undefined);
  if (reg) {
    await reg.update().catch(() => {});
    const incoming = reg.installing ?? reg.waiting;
    if (incoming) {
      // sw.js calls skipWaiting() on install; wait (briefly) until it is in charge.
      await new Promise<void>((resolve) => {
        const done = () => incoming.state === 'activated' && resolve();
        incoming.addEventListener('statechange', done);
        done();
        setTimeout(resolve, 5000);
      });
    }
  }
  if ('caches' in window) for (const key of await caches.keys()) await caches.delete(key);
  await Promise.all(['/', '/index.html', '/sw.js', '/manifest.webmanifest'].map((u) => fetch(u, { cache: 'reload' }).catch(() => {})));
  // A new query string makes the browser load the page from the network, not memory.
  const url = new URL(location.href);
  url.searchParams.set('refreshed', String(Date.now()));
  location.replace(url.toString());
}

/** Drop the `?refreshed=` marker left by refreshApp() from the address. */
export function clearRefreshMarker() {
  const url = new URL(location.href);
  if (!url.searchParams.has('refreshed')) return false;
  url.searchParams.delete('refreshed');
  history.replaceState(history.state, '', url.toString());
  return true;
}

// ── admin token for the service worker ──────────────────────
// The worker can't read localStorage; it reads the token from IndexedDB to approve/deny from a notification.

function kv<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest | void): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('twophase', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('kv');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction('kv', mode);
      const req = fn(tx.objectStore('kv'));
      tx.oncomplete = () => resolve(req ? (req.result as T) : undefined);
      tx.onerror = () => reject(tx.error);
    };
  });
}

export function shareTokenWithServiceWorker(token: string | null) {
  return kv('readwrite', (s) => (token ? s.put(token, 'adminToken') : s.delete('adminToken'))).catch(() => {});
}

// ── subscription ────────────────────────────────────────────

function base64UrlToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function sameKey(a: ArrayBuffer | null | undefined, b: Uint8Array): boolean {
  if (!a || a.byteLength !== b.byteLength) return false;
  const av = new Uint8Array(a);
  return av.every((x, i) => x === b[i]);
}

export async function currentSubscription(): Promise<PushSubscription | null> {
  if (!pushSupported) return null;
  const reg = await navigator.serviceWorker.getRegistration();
  return (await reg?.pushManager.getSubscription()) ?? null;
}

/** Must be called from a user gesture (Safari requires it for the permission prompt). */
export async function enablePush(api: Api): Promise<void> {
  const permission = await Notification.requestPermission();
  if (permission !== 'granted') throw new Error('Notification permission was not granted.');
  const reg = await navigator.serviceWorker.ready;
  const key = base64UrlToBytes((await api.pushConfig()).vapidPublicKey);

  let sub = await reg.pushManager.getSubscription();
  // A subscription made with a different VAPID key (e.g. the server's keys changed) is useless.
  if (sub && !sameKey(sub.options.applicationServerKey, key)) {
    await sub.unsubscribe();
    sub = null;
  }
  sub ??= await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
  await api.savePushSubscription(sub.toJSON());
}

export async function disablePush(api: Api): Promise<void> {
  const sub = await currentSubscription();
  if (!sub) return;
  await api.deletePushSubscription(sub.endpoint).catch(() => {});
  await sub.unsubscribe();
}

/** Re-send an existing subscription so the server knows it (e.g. after a database reset). */
export async function syncPushSubscription(api: Api): Promise<void> {
  const sub = await currentSubscription();
  if (sub && Notification.permission === 'granted') await api.savePushSubscription(sub.toJSON());
}

/** Remove the notification for an approval that has been decided (here, on another device, or timed out). */
export async function closeApprovalNotification(approvalId: string) {
  const reg = await navigator.serviceWorker?.getRegistration();
  for (const n of (await reg?.getNotifications({ tag: `approval:${approvalId}` })) ?? []) n.close();
}
