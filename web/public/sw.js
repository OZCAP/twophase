/* Service worker: receives Web Push for approvals and lets you approve/deny from the notification. */

/** Bump when this file changes, so diagnostics show which worker a device is running. */
const SW_VERSION = 'nav-6';
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

/** Report a step to the proxy's diagnostics log (GET /admin/api/client-log). Never throws. */
function log(event, detail) {
  return api('/client-log', { method: 'POST', body: JSON.stringify({ source: 'sw', event, detail: { v: SW_VERSION, ...detail } }) }).catch(() => {});
}

// Pages listen here too: a second path for "navigate", in case client.postMessage is lost.
const channel = new BroadcastChannel('twophase');

// ── lifecycle ───────────────────────────────────────────────

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(log('install'));
});
// Pages ask which worker is running (Settings shows it; diagnostics log it).
self.addEventListener('message', (event) => {
  if (event.data?.type !== 'version') return;
  event.source?.postMessage({ type: 'version', v: SW_VERSION });
  channel.postMessage({ type: 'version', v: SW_VERSION });
});
self.addEventListener('activate', (event) => event.waitUntil(Promise.all([self.clients.claim(), log('activate')])));

// ── push ────────────────────────────────────────────────────

self.addEventListener('push', (event) => {
  let data;
  try {
    data = event.data.json();
  } catch {
    data = { type: 'message', title: 'Twophase', body: event.data ? event.data.text() : '', url: '/' };
  }
  void log('push', { type: data.type, approvalId: data.approvalId ?? null });
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
  void log('notificationclick', { action: event.action || null, url: data.url || null });
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

/**
 * Opens the app at `url`, trying every path iOS might honour:
 *  1. store the target in IndexedDB (the page reads it whenever it becomes visible, and polls for a
 *     few seconds after: iOS can show the page before this handler has run);
 *  2. tell open windows, by postMessage and by BroadcastChannel;
 *  3. if no page confirms within ~1.5s, navigate the window to the URL itself (a reload);
 *  4. with no window at all, open one.
 */
async function openApp(url) {
  const target = new URL(url, self.location.origin).href;
  const nonce = Math.random().toString(36).slice(2);
  await kv('readwrite', (s) => s.put({ url: target, at: Date.now(), nonce }, 'pendingNavigation')).catch(() => {});
  const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  const existing = windows.filter((w) => new URL(w.url).origin === self.location.origin);
  await log('openApp', { target, windows: existing.map((w) => ({ url: w.url, focused: w.focused, visibility: w.visibilityState })) });
  if (existing.length === 0) {
    const opened = await self.clients.openWindow(target).catch((e) => (log('openWindow failed', { error: String(e) }), null));
    return log('openWindow', { ok: !!opened, url: opened?.url ?? null });
  }

  const acked = new Promise((resolve) => {
    const onAck = (e) => e.data?.type === 'navigated' && e.data.nonce === nonce && resolve(true);
    channel.addEventListener('message', onAck);
    self.addEventListener('message', onAck);
    setTimeout(() => resolve(false), 1500);
  });
  for (const w of existing) w.postMessage({ type: 'navigate', url: target, nonce });
  channel.postMessage({ type: 'navigate', url: target, nonce });
  const win = existing.find((w) => w.focused) ?? existing[0];
  const focus = await win.focus().then(() => 'ok', (e) => String(e));

  if (await acked) return log('navigated by page', { focus });
  // No page answered: load the URL in the window directly.
  const navigated = await win.navigate(target).then((c) => (c ? c.url : 'null client'), (e) => `failed: ${e}`);
  return log('client.navigate', { focus, result: navigated });
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
