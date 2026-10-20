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
