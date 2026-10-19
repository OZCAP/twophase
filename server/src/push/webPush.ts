import webpush from 'web-push';
import type { PushSubscription, Store } from '../store.js';

export interface VapidKeys {
  publicKey: string;
  privateKey: string;
  /** `mailto:` or `https:` contact the push service can reach. Apple rejects placeholder domains. */
  subject: string;
}

export interface WebPushOptions {
  /** Seconds the push service should hold the message for an offline device. */
  ttlSeconds: number;
  urgency?: 'very-low' | 'low' | 'normal' | 'high';
  /** Messages with the same topic replace each other while undelivered (≤32 url-safe chars). */
  topic?: string;
}

export interface SendResult {
  sent: number;
  failed: number;
  removed: number;
}

/**
 * Keys come from VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY, or are generated on first boot and kept
 * in the settings table. Changing them invalidates every existing browser subscription.
 */
export function resolveVapidKeys(store: Store, env: { publicKey?: string; privateKey?: string; subject: string }): VapidKeys {
  if (env.publicKey && env.privateKey) return { publicKey: env.publicKey, privateKey: env.privateKey, subject: env.subject };
  let publicKey = store.getSetting('vapid_public_key');
  let privateKey = store.getSetting('vapid_private_key');
  if (!publicKey || !privateKey) {
    ({ publicKey, privateKey } = webpush.generateVAPIDKeys());
    store.setSetting('vapid_public_key', publicKey);
    store.setSetting('vapid_private_key', privateKey);
  }
  return { publicKey, privateKey, subject: env.subject };
}

/**
 * Sends encrypted Web Push messages (RFC 8030/8291, VAPID RFC 8292) to subscribed PWAs.
 * web-push builds and encrypts the request; we send it with fetch so delivery is easy to observe and test.
 */
export class WebPushSender {
  constructor(
    private store: Store,
    private vapid: VapidKeys,
  ) {}

  get publicKey() {
    return this.vapid.publicKey;
  }

  async sendToAll(payload: object, opts: WebPushOptions): Promise<SendResult> {
    const result: SendResult = { sent: 0, failed: 0, removed: 0 };
    await Promise.all(
      this.store.listPushSubscriptions().map(async (sub) => {
        try {
          const outcome = await this.send(sub, payload, opts);
          if (outcome === 'removed') result.removed++;
          else result.sent++;
        } catch (err) {
          result.failed++;
          console.warn(`[web-push] ${new URL(sub.endpoint).host}: ${err instanceof Error ? err.message : err}`);
        }
      }),
    );
    return result;
  }

  private async send(sub: PushSubscription, payload: object, opts: WebPushOptions): Promise<'sent' | 'removed'> {
    const details = webpush.generateRequestDetails(
      { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
      JSON.stringify(payload),
      {
        vapidDetails: this.vapid,
        TTL: Math.max(0, Math.round(opts.ttlSeconds)),
        urgency: opts.urgency ?? 'normal',
        topic: opts.topic,
        contentEncoding: 'aes128gcm',
      },
    );
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(details.headers as Record<string, string | number>)) {
      if (k.toLowerCase() !== 'content-length') headers[k] = String(v);
    }
    const res = await fetch(details.endpoint, {
      method: details.method,
      headers,
      body: new Uint8Array(details.body),
      signal: AbortSignal.timeout(10_000),
    });
    // 404/410: the browser unsubscribed or the subscription expired. Forget it.
    if (res.status === 404 || res.status === 410) {
      this.store.deletePushSubscription(sub.endpoint);
      return 'removed';
    }
    if (!res.ok) throw new Error(`push service responded ${res.status} ${(await res.text()).slice(0, 200)}`);
    this.store.markPushDelivered(sub.endpoint);
    return 'sent';
  }
}
