import { describe, expect, it } from 'vitest';
import { clock } from './ui';

describe('clock', () => {
  it('ticks as m:ss, h:mm:ss, then days', () => {
    expect(clock(0)).toBe('0:00');
    expect(clock(65.9)).toBe('1:05');
    expect(clock(3600 + 2 * 60 + 3)).toBe('1:02:03');
    expect(clock(2 * 86400 + 3600 + 5)).toBe('2d 01:00:05');
  });
  it('never goes negative', () => expect(clock(-4)).toBe('0:00'));
});
