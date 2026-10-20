import type { Store } from './store.js';

const HOUR = 3600_000;
const DAY = 24 * HOUR;

/** Background upkeep for the proxy's own database: hourly, trims activity older than the retention period. */
export class Housekeeping {
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private store: Store,
    private opts: { auditRetentionDays: number },
  ) {}

  start() {
    if (this.opts.auditRetentionDays <= 0) return;
    this.prune();
    this.timer = setInterval(() => this.prune(), HOUR);
    this.timer.unref();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  prune(now = Date.now()) {
    const removed = this.store.pruneHistory(new Date(now - this.opts.auditRetentionDays * DAY));
    if (removed.audit || removed.approvals) console.log(`[housekeeping] removed ${removed.audit} activity entries and ${removed.approvals} approvals older than ${this.opts.auditRetentionDays} days`);
    return removed;
  }
}
