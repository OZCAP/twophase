import type { StatementResult } from './types.js';

export const MAX_CELL_CHARS = 10_000;
const MAX_RESULT_BYTES = 256 * 1024;

/** A result cell as JSON: long text cut, bytes as hex, bigints as strings. */
export function jsonCell(v: unknown): unknown {
  if (Buffer.isBuffer(v)) return `\\x${v.subarray(0, MAX_CELL_CHARS / 2).toString('hex')}${v.length > MAX_CELL_CHARS / 2 ? '…' : ''}`;
  if (typeof v === 'string' && v.length > MAX_CELL_CHARS) return `${v.slice(0, MAX_CELL_CHARS)}…`;
  if (typeof v === 'bigint') return v.toString();
  return v;
}

/** Duplicate column names get a suffix (`id`, `id_2`) so rows can be objects. */
export function uniqueNames(names: string[]): string[] {
  const seen = new Map<string, number>();
  return names.map((n) => {
    const count = (seen.get(n) ?? 0) + 1;
    seen.set(n, count);
    return count === 1 ? n : `${n}_${count}`;
  });
}

/** Keep the whole response under ~256 KB by dropping trailing rows. */
export function capResultSize(results: StatementResult[]): StatementResult[] {
  let size = JSON.stringify(results).length;
  for (let i = results.length - 1; i >= 0 && size > MAX_RESULT_BYTES; i--) {
    const r = results[i];
    while (r.rows.length > 0 && size > MAX_RESULT_BYTES) {
      const removed = r.rows.splice(Math.floor(r.rows.length / 2));
      size -= JSON.stringify(removed).length;
      r.truncated = true;
    }
  }
  return results;
}
