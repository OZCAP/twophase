import type { Config } from '../config.js';
import { previewSql } from '../events.js';
import type { Approval, DatabaseConfig, ProxyUser, Store } from '../store.js';
import { ApnsSender } from './apns.js';
import { resolveVapidKeys, WebPushSender, type SendResult } from './webPush.js';

/** Payload the PWA service worker understands (web/public/sw.js). */
export type WebPushPayload =
  | { type: 'approval'; approvalId: string; title: string; body: string; url: string; expiresAt: string }
  | { type: 'message'; title: string; body: string; url: string };

/** Fans notifications out to every channel: Web Push (PWA) always, APNs when configured. */
export class PushService {
  readonly web: WebPushSender;
  private apns: ApnsSender | null;

  constructor(store: Store, config: Config) {
    this.web = new WebPushSender(store, resolveVapidKeys(store, config.vapid));
    this.apns = config.apns ? new ApnsSender(store, config.apns) : null;
  }

  get apnsEnabled() {
    return this.apns !== null;
  }

  async notifyApproval(approval: Approval, db: DatabaseConfig, user: ProxyUser) {
    const title = approvalTitle(approval);
    const preview = previewSql(approval.sql);
    const who = `${user.name} via ${approval.surface === 'wire' ? 'Postgres' : 'MCP'} → ${db.name}`;
    const ttlSeconds = (approval.expiresAt.getTime() - Date.now()) / 1000;

    const webPayload: WebPushPayload = {
      type: 'approval',
      approvalId: approval.id,
      title,
      body: `${who}\n${preview}`,
      url: `/#/approvals/${approval.id}`,
      expiresAt: approval.expiresAt.toISOString(),
    };
    await Promise.all([
      this.web.sendToAll(webPayload, { ttlSeconds, urgency: 'high', topic: approval.id.replaceAll('-', '') }),
      this.apns?.sendToAll(
        {
          aps: {
            alert: { title, subtitle: who, body: preview },
            sound: 'default',
            category: 'APPROVAL_REQUEST',
            'thread-id': db.id,
            'interruption-level': 'time-sensitive',
          },
          approvalId: approval.id,
        },
        {
          'apns-expiration': String(Math.floor(approval.expiresAt.getTime() / 1000)),
          'apns-collapse-id': approval.id,
        },
      ),
    ]).catch((err) => console.warn('[push]', err));
  }

  sendTest(): Promise<SendResult> {
    const payload: WebPushPayload = {
      type: 'message',
      title: 'Twophase',
      body: 'Push notifications are working on this device.',
      url: '/#/settings',
    };
    return this.web.sendToAll(payload, { ttlSeconds: 60, urgency: 'normal' });
  }

  close() {
    this.apns?.close();
  }
}

/** e.g. "Approve write on orders?", "Approve ddl + write on orders, customers +1?" */
export function approvalTitle(approval: Pick<Approval, 'asked'>): string {
  const ops = [...new Set(approval.asked.map((a) => a.op))];
  const tables = [...new Set(approval.asked.map((a) => a.table).filter((t): t is string => !!t))];
  const on = tables.length ? ` on ${tables.slice(0, 2).join(', ')}${tables.length > 2 ? ` +${tables.length - 2}` : ''}` : '';
  return `Approve ${ops.join(' + ')}${on}?`;
}
