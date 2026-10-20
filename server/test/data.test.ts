import { chmodSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db/index.js';

const dirs: string[] = [];
const tempDir = () => {
  const d = mkdtempSync(path.join(tmpdir(), 'twophase-data-'));
  dirs.push(d);
  return d;
};
const mode = (p: string) => statSync(p).mode & 0o777;

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('data directory permissions', () => {
  it('locks down a data directory and files created before it was enforced', () => {
    const dir = tempDir();
    chmodSync(dir, 0o755);
    writeFileSync(path.join(dir, 'proxy.db-old'), 'x', { mode: 0o644 });
    const { sqlite } = openDatabase(dir);
    sqlite.close();
    expect(mode(dir)).toBe(0o700);
    expect(mode(path.join(dir, 'proxy.db-old'))).toBe(0o600);
  });

  it('creates a missing data directory private', () => {
    const dir = path.join(tempDir(), 'nested', 'data');
    openDatabase(dir).sqlite.close();
    expect(mode(dir)).toBe(0o700);
  });
});

describe('housekeeping', () => {
  const day = 24 * 3600_000;

  it('prunes activity and decided approvals past the retention period, keeping pending ones', async () => {
    const { Store } = await import('../src/store.js');
    const { Housekeeping } = await import('../src/housekeeping.js');
    const store = new Store(':memory:');
    const sqlite = (store as any).sqlite;
    // Raw rows without their database/client: only the history tables matter here.
    sqlite.pragma('foreign_keys = OFF');
    const old = Date.now() - 100 * day;
    const recent = Date.now() - day;
    const approval = (id: string, at: number, status: string) =>
      sqlite.prepare(
        `INSERT INTO approvals (id, database_id, user_id, surface, sql, statements, asked, operations, tables, status, created_at, expires_at)
         VALUES (?, 'd', 'u', 'mcp', 'x', '[]', '[]', '[]', '[]', ?, ?, ?)`,
      ).run(id, status, at, at);
    approval('old-decided', old, 'approved');
    approval('old-pending', old, 'pending');
    approval('recent-decided', recent, 'denied');
    const audit = (at: number) =>
      sqlite.prepare(`INSERT INTO audit (ts, database_id, user_id, surface, sql, operations, tables, decision) VALUES (?, 'd', 'u', 'mcp', 'x', '[]', '[]', 'allowed')`).run(at);
    audit(old);
    audit(recent);

    const hk = new Housekeeping(store, { auditRetentionDays: 90 });
    expect(hk.prune()).toEqual({ audit: 1, approvals: 1 });
    expect(sqlite.prepare('SELECT id FROM approvals ORDER BY id').all().map((r: any) => r.id)).toEqual(['old-pending', 'recent-decided']);
    expect(sqlite.prepare('SELECT count(*) AS n FROM audit').get().n).toBe(1);
    store.close();
  });
});
