import { chmodSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';
import path from 'node:path';
import type { Store } from './store.js';

const HOUR = 3600_000;
const DAY = 24 * HOUR;
const BACKUP_FILE = /^proxy-\d{8}T\d{6}Z\.db$/;

export interface HousekeepingOptions {
  dataDir: string;
  auditRetentionDays: number;
  backupIntervalHours: number;
  backupKeep: number;
}

/**
 * Background upkeep for the proxy's own database: trims activity older than the retention period
 * (hourly) and writes rotated backups to DATA_DIR/backups. Backups hold the same secrets as the
 * database, so they get the same 0600 permissions.
 */
export class Housekeeping {
  private timers: NodeJS.Timeout[] = [];
  private backupDir: string | null;

  constructor(
    private store: Store,
    private opts: HousekeepingOptions,
  ) {
    this.backupDir = opts.dataDir === ':memory:' || opts.backupIntervalHours <= 0 ? null : path.join(opts.dataDir, 'backups');
  }

  start() {
    if (this.opts.auditRetentionDays > 0) {
      this.prune();
      this.every(HOUR, () => this.prune());
    }
    if (this.backupDir) {
      const interval = this.opts.backupIntervalHours * HOUR;
      // After a restart, only back up if the newest backup is older than the interval.
      const newest = this.backups().at(-1);
      const age = newest ? Date.now() - statSync(path.join(this.backupDir, newest)).mtimeMs : Infinity;
      if (age >= interval) void this.backup().catch((err) => console.warn('[backup]', err));
      this.every(interval, () => void this.backup().catch((err) => console.warn('[backup]', err)));
    }
  }

  stop() {
    for (const t of this.timers.splice(0)) clearInterval(t);
  }

  prune(now = Date.now()) {
    const removed = this.store.pruneHistory(new Date(now - this.opts.auditRetentionDays * DAY));
    if (removed.audit || removed.approvals) console.log(`[housekeeping] removed ${removed.audit} activity entries and ${removed.approvals} approvals older than ${this.opts.auditRetentionDays} days`);
    return removed;
  }

  /** Writes a new backup and deletes the oldest beyond `backupKeep`. Returns the new file's path. */
  async backup(now = new Date()): Promise<string> {
    if (!this.backupDir) throw new Error('Backups are turned off');
    mkdirSync(this.backupDir, { recursive: true, mode: 0o700 });
    const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
    const file = path.join(this.backupDir, `proxy-${stamp}.db`);
    await this.store.backup(file);
    chmodSync(file, 0o600);
    const all = this.backups();
    for (const old of all.slice(0, Math.max(0, all.length - this.opts.backupKeep))) rmSync(path.join(this.backupDir, old), { force: true });
    return file;
  }

  /** Backup file names, oldest first. */
  backups(): string[] {
    if (!this.backupDir) return [];
    try {
      return readdirSync(this.backupDir).filter((f) => BACKUP_FILE.test(f)).sort();
    } catch {
      return [];
    }
  }

  private every(ms: number, fn: () => void) {
    const t = setInterval(fn, ms);
    t.unref();
    this.timers.push(t);
  }
}
