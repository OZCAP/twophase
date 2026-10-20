import type { Api } from './api';

/** Web Push needs a service worker, the Push API and notifications. */
export const pushSupported = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;

/** iOS/iPadOS only allow Web Push for apps added to the Home Screen. */
export const isIos = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
export const isStandalone =
  window.matchMedia('(display-mode: standalone)').matches || (navigator as { standalone?: boolean }).standalone === true;

/** How long a tapped notification's target stays valid if the app only wakes up later. */
const PENDING_NAVIGATION_MS = 5 * 60_000;

function navigateTo(url: string) {
  const target = new URL(url, location.origin);
  if (target.origin === location.origin && target.hash && location.hash !== target.hash) location.hash = target.hash;
}

/** Go where the last tapped notification pointed, if the app hasn't been there yet. */
async function consumePendingNavigation() {
  const pending = await kv<{ url: string; at: number }>('readonly', (s) => s.get('pendingNavigation')).catch(() => undefined);
  if (!pending) return;
  await kv('readwrite', (s) => s.delete('pendingNavigation')).catch(() => {});
  if (Date.now() - pending.at < PENDING_NAVIGATION_MS) navigateTo(pending.url);
}

export async function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  // The service worker asks an open window to navigate when a notification is tapped, and also leaves
  // the target in IndexedDB in case the message never arrives (iOS) or the app opened at its start URL.
  navigator.serviceWorker.addEventListener('message', (e) => {
    if (e.data?.type === 'navigate' && typeof e.data.url === 'string') {
      navigateTo(e.data.url);
      void kv('readwrite', (s) => s.delete('pendingNavigation')).catch(() => {});
    }
  });
  document.addEventListener('visibilitychange', () => document.visibilityState === 'visible' && void consumePendingNavigation());
  window.addEventListener('focus', () => void consumePendingNavigation());
  void consumePendingNavigation();
  await navigator.serviceWorker.register('/sw.js');
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
