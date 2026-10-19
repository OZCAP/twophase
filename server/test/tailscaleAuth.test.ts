import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { isAllowed, type TailscaleIdentity } from '../src/tailscaleAuth.js';
import { startProxy } from './helpers.js';

const DEVICES: Record<string, TailscaleIdentity> = {
  '100.0.0.1': { ip: '100.0.0.1', node: 'iphone', tags: ['tag:admin-client'], login: null },
  '100.0.0.2': { ip: '100.0.0.2', node: 'staging', tags: ['tag:admin-accessible'], login: null },
  '100.0.0.3': { ip: '100.0.0.3', node: 'laptop', tags: [], login: 'alice@github' },
};

describe('isAllowed', () => {
  it('matches tags, owner logins and machine names', () => {
    expect(isAllowed(DEVICES['100.0.0.1'], ['tag:admin-client'])).toBe(true);
    expect(isAllowed(DEVICES['100.0.0.2'], ['tag:admin-client'])).toBe(false);
    expect(isAllowed(DEVICES['100.0.0.3'], ['alice@github'])).toBe(true);
    expect(isAllowed(DEVICES['100.0.0.3'], ['laptop'])).toBe(true);
    expect(isAllowed(DEVICES['100.0.0.3'], ['bob@github', 'iphone'])).toBe(false);
  });
});

describe('ADMIN_AUTH=tailscale', () => {
  let proxy: Awaited<ReturnType<typeof startProxy>>;
  const as = (ip: string | null, path = '/status', init: RequestInit = {}) =>
    fetch(`${proxy.base}/admin/api${path}`, { ...init, headers: { ...(ip && { 'x-forwarded-for': ip }), ...init.headers } });

  beforeAll(async () => {
    proxy = await startProxy(
      { adminAuth: 'tailscale', tailscaleAllow: ['tag:admin-client'] },
      { whois: async (ip) => DEVICES[ip] ?? null },
    );
  });
  afterAll(async () => proxy?.close());

  it('lets an allowed device in without a token and reports who it is', async () => {
    const res = await as('100.0.0.1');
    expect(res.status).toBe(200);
    expect((await res.json()).auth).toEqual({ mode: 'tailscale', device: 'iphone', login: null });
  });

  it('rejects other tailnet devices — e.g. an agent host approving its own calls', async () => {
    const res = await as('100.0.0.2', '/approvals');
    expect(res.status).toBe(403);
    expect((await res.json()).error).toMatch(/staging/);
  });

  it('rejects requests without a tailnet identity, and ignores the old admin token', async () => {
    expect((await as(null)).status).toBe(401);
    expect((await as('8.8.8.8')).status).toBe(401);
    expect((await as(null, '/status', { headers: { authorization: 'Bearer test-admin-token' } })).status).toBe(401);
  });

  it('refuses to start unless bound to loopback with an allow-list', async () => {
    await expect(startProxy({ adminAuth: 'tailscale', tailscaleAllow: ['tag:x'], host: '0.0.0.0' })).rejects.toThrow(/HOST=127.0.0.1/);
    await expect(startProxy({ adminAuth: 'tailscale', tailscaleAllow: [] })).rejects.toThrow(/ADMIN_TAILSCALE_ALLOW/);
  });
});
