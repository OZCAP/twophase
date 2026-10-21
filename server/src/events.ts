import { EventEmitter } from 'node:events';
import type { Approval, AuditEntry, Grant } from './store.js';

export interface EventMap {
  'approval.created': Approval;
  'approval.resolved': Approval;
  'grant.created': Grant;
  'grant.revoked': { id: string };
  audit: AuditEntry;
  /** Internal notification: close authenticated sessions when credentials/access change. */
  'access.changed': { userId?: string; databaseId?: string };
}

export type EventName = keyof EventMap;
export const EVENT_NAMES: EventName[] = ['approval.created', 'approval.resolved', 'grant.created', 'grant.revoked', 'audit'];

/** In-process event bus feeding the admin SSE stream. */
export class EventBus {
  private emitter = new EventEmitter().setMaxListeners(0);

  emit<K extends EventName>(name: K, payload: EventMap[K]) {
    this.emitter.emit(name, payload);
  }

  on<K extends EventName>(name: K, fn: (payload: EventMap[K]) => void): () => void {
    this.emitter.on(name, fn);
    return () => this.emitter.off(name, fn);
  }
}

/** One-line SQL preview for notifications and lists. */
export function previewSql(sql: string, max = 180): string {
  const text = sql.replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
