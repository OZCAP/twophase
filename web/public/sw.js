/* Service worker: receives Web Push for approvals and lets you approve/deny from the notification. */

const ICON = '/icons/icon-192.png';
const BADGE = '/icons/badge-96.png';

// ── admin token (token mode only), shared with the page via IndexedDB (src/push.ts) ──

function kv(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('twophase', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('kv');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction('kv', mode);
      const req = fn(tx.objectStore('kv'));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
    };
  });
}
const getToken = () => kv('readonly', (s) => s.get('adminToken'));

async function api(path, init = {}) {
  // No token when the server authenticates this device via Tailscale.
  const token = await getToken();
  const res = await fetch(`/admin/api${path}`, {
    ...init,
    headers: { ...(token && { authorization: `Bearer ${token}` }), 'content-type': 'application/json', ...init.headers },
  });
  if (!res.ok) throw new Error((await res.json().catch(() => null))?.error ?? `HTTP ${res.status}`);
  return res.status === 204 ? null : res.json();
}

// ── lifecycle ───────────────────────────────────────────────

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// ── push ────────────────────────────────────────────────────

self.addEventListener('push', (event) => {
  let data;
  try {
    data = event.data.json();
  } catch {
    data = { type: 'message', title: 'Twophase', body: event.data ? event.data.text() : '', url: '/' };
  }
  // Always show something: Safari revokes subscriptions whose pushes don't display a notification.
  event.waitUntil(
    data.type === 'approval'
      ? self.registration.showNotification(data.title, {
          body: data.body,
          tag: `approval:${data.approvalId}`,
          renotify: true,
          requireInteraction: true,
          icon: ICON,
          badge: BADGE,
          data,
          // Action buttons show on Chrome/Edge/Android; iOS/macOS Safari ignore them (tap opens the app).
          actions: [
            { action: 'approve', title: 'Approve' },
            { action: 'deny', title: 'Deny' },
          ],
        })
      : self.registration.showNotification(data.title, { body: data.body, icon: ICON, badge: BADGE, data }),
  );
});

self.addEventListener('notificationclick', (event) => {
  const data = event.notification.data || {};
  event.notification.close();
  if (data.type === 'approval' && (event.action === 'approve' || event.action === 'deny')) {
    event.waitUntil(decide(data, event.action));
  } else {
    event.waitUntil(openApp(data.url || '/'));
  }
});

async function decide(data, decision) {
  try {
    await api(`/approvals/${data.approvalId}/decision`, { method: 'POST', body: JSON.stringify({ decision }) });
  } catch (err) {
    await self.registration.showNotification(`Couldn't ${decision}: ${data.title}`, {
      body: err.message,
      tag: `approval-error:${data.approvalId}`,
      icon: ICON,
      badge: BADGE,
      data: { type: 'message', url: data.url },
    });
  }
}

async function openApp(url) {
  const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  const existing = windows.find((w) => new URL(w.url).origin === self.location.origin);
  if (existing) {
    existing.postMessage({ type: 'navigate', url });
    return existing.focus();
  }
  return self.clients.openWindow(url);
}

// Browsers may rotate a subscription; re-register the new one with the proxy.
self.addEventListener('pushsubscriptionchange', (event) => {
  event.waitUntil(
    (async () => {
      const key =
        event.oldSubscription?.options?.applicationServerKey ?? (await api('/push/config')).vapidPublicKey;
      const sub = event.newSubscription ?? (await self.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key }));
      await api('/push/subscriptions', { method: 'POST', body: JSON.stringify(sub.toJSON()) });
      if (event.oldSubscription) {
        await api(`/push/subscriptions?endpoint=${encodeURIComponent(event.oldSubscription.endpoint)}`, { method: 'DELETE' }).catch(() => {});
      }
    })(),
  );
});
